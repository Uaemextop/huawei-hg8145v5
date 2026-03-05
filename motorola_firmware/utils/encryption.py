"""
Encryption utilities for the Motorola Firmware Downloader.

Provides Fernet symmetric encryption for sensitive config values
and PBKDF2-based password hashing for credential storage.

Uses the ``cryptography`` library.  Fernet provides AES-128 in CBC mode
with PKCS7 padding and HMAC-SHA256 authentication.
"""

import base64
import hashlib
import os
from typing import Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from motorola_firmware.utils.logger import log


class EncryptionError(Exception):
    """Raised when encryption or decryption operations fail."""


def generate_key() -> bytes:
    """Generate a new random Fernet-compatible encryption key.

    Returns:
        A URL-safe base64-encoded 32-byte key.
    """
    return Fernet.generate_key()


def derive_key_from_password(
    password: str, salt: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Derive a Fernet key from a password using PBKDF2-SHA256.

    Args:
        password: The password to derive the key from.
        salt: Optional salt bytes. Generated randomly if not provided.

    Returns:
        Tuple of (derived_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend(),
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return derived_key, salt


def encrypt(text: str, key: bytes) -> str:
    """Encrypt plaintext string using Fernet symmetric encryption.

    Args:
        text: The plaintext string to encrypt.
        key: Fernet-compatible encryption key.

    Returns:
        Base64-encoded encrypted string.

    Raises:
        EncryptionError: If encryption fails.
    """
    try:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode("utf-8"))
        return encrypted.decode("utf-8")
    except Exception as error:
        log.error("[CRYPTO] Encryption failed: %s", type(error).__name__)
        raise EncryptionError("Failed to encrypt data") from error


def decrypt(encrypted_text: str, key: bytes) -> str:
    """Decrypt an encrypted string using Fernet symmetric encryption.

    Args:
        encrypted_text: Base64-encoded encrypted string.
        key: Fernet-compatible encryption key (must match encrypt key).

    Returns:
        The decrypted plaintext string.

    Raises:
        EncryptionError: If decryption fails or token is invalid.
    """
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_text.encode("utf-8"))
        return decrypted.decode("utf-8")
    except InvalidToken:
        log.error("[CRYPTO] Decryption failed: invalid token or key")
        raise EncryptionError("Invalid encryption key or corrupted data")
    except Exception as error:
        log.error("[CRYPTO] Decryption failed: %s", type(error).__name__)
        raise EncryptionError("Failed to decrypt data") from error


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-SHA256 with a random salt.

    Format: ``base64(salt):base64(hash)``

    Args:
        password: The plaintext password to hash.

    Returns:
        A string containing the salt and hash separated by a colon.
    """
    salt = os.urandom(32)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100000
    )
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(password_hash).decode("utf-8")
    return f"{salt_b64}:{hash_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash.

    Args:
        password: The plaintext password to verify.
        stored_hash: The stored hash string in ``salt:hash`` format.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        salt_b64, hash_b64 = stored_hash.split(":")
        salt = base64.b64decode(salt_b64)
        stored_password_hash = base64.b64decode(hash_b64)
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100000
        )
        return computed_hash == stored_password_hash
    except (ValueError, Exception):
        return False
