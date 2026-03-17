"""Encryption and hashing utilities for Motorola Firmware Downloader.

Provides AES-256 encryption/decryption and password hashing using industry-standard
cryptographic libraries.
"""

import base64
import hashlib
import secrets
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# Constants for encryption
AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 16  # 128 bits
PBKDF2_ITERATIONS = 100000


class EncryptionError(Exception):
    """Exception raised when encryption/decryption fails."""
    pass


class DecryptionError(Exception):
    """Exception raised when decryption fails."""
    pass


def generate_key(password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Generate AES-256 key from password using PBKDF2.

    Args:
        password: Password to derive key from
        salt: Optional salt (generated if not provided)

    Returns:
        Tuple of (key, salt)

    Raises:
        EncryptionError: If key generation fails
    """
    try:
        if salt is None:
            salt = secrets.token_bytes(AES_BLOCK_SIZE)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt
    except Exception as e:
        raise EncryptionError(f"Failed to generate encryption key: {e}")


def generate_random_key() -> bytes:
    """Generate a random AES-256 key.

    Returns:
        Random 256-bit key

    Examples:
        >>> key = generate_random_key()
        >>> len(key)
        32
    """
    return secrets.token_bytes(AES_KEY_SIZE)


def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypt plaintext using AES-256-CBC.

    Args:
        plaintext: Text to encrypt
        key: 256-bit encryption key

    Returns:
        Base64-encoded ciphertext with IV prepended

    Raises:
        EncryptionError: If encryption fails

    Examples:
        >>> key = generate_random_key()
        >>> encrypted = encrypt("secret text", key)
        >>> isinstance(encrypted, str)
        True
    """
    try:
        # Generate random IV
        iv = secrets.token_bytes(AES_BLOCK_SIZE)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Pad plaintext to block size
        plaintext_bytes = plaintext.encode("utf-8")
        padding_length = AES_BLOCK_SIZE - (len(plaintext_bytes) % AES_BLOCK_SIZE)
        padded = plaintext_bytes + bytes([padding_length] * padding_length)

        # Encrypt
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        # Prepend IV to ciphertext and encode as base64
        return base64.b64encode(iv + ciphertext).decode("ascii")

    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}")


def decrypt(ciphertext_b64: str, key: bytes) -> str:
    """Decrypt AES-256-CBC ciphertext.

    Args:
        ciphertext_b64: Base64-encoded ciphertext with IV prepended
        key: 256-bit decryption key

    Returns:
        Decrypted plaintext

    Raises:
        DecryptionError: If decryption fails

    Examples:
        >>> key = generate_random_key()
        >>> encrypted = encrypt("secret", key)
        >>> decrypt(encrypted, key)
        'secret'
    """
    try:
        # Decode base64
        data = base64.b64decode(ciphertext_b64)

        # Extract IV and ciphertext
        iv = data[:AES_BLOCK_SIZE]
        ciphertext = data[AES_BLOCK_SIZE:]

        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # Decrypt
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = padded[-1]
        plaintext_bytes = padded[:-padding_length]

        return plaintext_bytes.decode("utf-8")

    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}")


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """Hash password using PBKDF2-HMAC-SHA256.

    Args:
        password: Password to hash
        salt: Optional salt (generated if not provided)

    Returns:
        Tuple of (hash_base64, salt_base64)

    Examples:
        >>> hash_val, salt = hash_password("mypassword")
        >>> len(hash_val) > 0
        True
    """
    if salt is None:
        salt = secrets.token_bytes(AES_BLOCK_SIZE)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    password_hash = kdf.derive(password.encode("utf-8"))

    return (
        base64.b64encode(password_hash).decode("ascii"),
        base64.b64encode(salt).decode("ascii")
    )


def verify_password(password: str, hash_b64: str, salt_b64: str) -> bool:
    """Verify password against stored hash.

    Args:
        password: Password to verify
        hash_b64: Base64-encoded password hash
        salt_b64: Base64-encoded salt

    Returns:
        True if password matches, False otherwise

    Examples:
        >>> hash_val, salt = hash_password("correct")
        >>> verify_password("correct", hash_val, salt)
        True
        >>> verify_password("wrong", hash_val, salt)
        False
    """
    try:
        salt = base64.b64decode(salt_b64)
        expected_hash = base64.b64decode(hash_b64)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        computed_hash = kdf.derive(password.encode("utf-8"))

        return secrets.compare_digest(computed_hash, expected_hash)
    except Exception:
        return False


def sha256_hash(text: str) -> str:
    """Compute SHA-256 hash of text.

    Args:
        text: Text to hash

    Returns:
        Hex-encoded SHA-256 hash

    Examples:
        >>> sha256_hash("test")
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
