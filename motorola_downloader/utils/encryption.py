"""Encryption utilities for Motorola Firmware Downloader.

Provides symmetric encryption (Fernet) for general data and bcrypt-style
hashing for passwords. All sensitive data stored in config.ini should be
encrypted using these utilities.
"""

import base64
import hashlib
import os
import secrets
from typing import Optional

from motorola_downloader.exceptions import EncryptionError
from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: cryptography
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet, InvalidToken
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_LENGTH = 32  # 256-bit key
SALT_LENGTH = 16


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_key() -> str:
    """Generate a new Fernet-compatible encryption key.

    Returns:
        A URL-safe base64-encoded key string suitable for Fernet encryption.

    Raises:
        EncryptionError: If the cryptography library is not available.
    """
    if not _CRYPTO_AVAILABLE:
        raise EncryptionError(
            "cryptography library required: pip install cryptography"
        )
    try:
        key = Fernet.generate_key()
        _logger.info("New encryption key generated")
        return key.decode("ascii")
    except Exception as exc:
        _logger.error("Failed to generate encryption key: %s", exc)
        raise EncryptionError(f"Key generation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt(text: str, key: str) -> str:
    """Encrypt plaintext using Fernet symmetric encryption.

    Args:
        text: The plaintext string to encrypt.
        key: A Fernet-compatible key string.

    Returns:
        Base64-encoded encrypted string.

    Raises:
        EncryptionError: If encryption fails or library is not available.
    """
    if not _CRYPTO_AVAILABLE:
        raise EncryptionError(
            "cryptography library required: pip install cryptography"
        )
    if not text:
        raise EncryptionError("Cannot encrypt empty text")
    if not key:
        raise EncryptionError("Encryption key cannot be empty")

    try:
        fernet = Fernet(key.encode("ascii"))
        encrypted = fernet.encrypt(text.encode("utf-8"))
        _logger.info("Data encrypted successfully")
        return encrypted.decode("ascii")
    except Exception as exc:
        _logger.error("Encryption failed: %s", exc)
        raise EncryptionError(f"Encryption failed: {exc}") from exc


def decrypt(encrypted_text: str, key: str) -> str:
    """Decrypt a Fernet-encrypted string.

    Args:
        encrypted_text: The base64-encoded encrypted string.
        key: The Fernet-compatible key used for encryption.

    Returns:
        The decrypted plaintext string.

    Raises:
        EncryptionError: If decryption fails, key is wrong, or library unavailable.
    """
    if not _CRYPTO_AVAILABLE:
        raise EncryptionError(
            "cryptography library required: pip install cryptography"
        )
    if not encrypted_text:
        raise EncryptionError("Cannot decrypt empty text")
    if not key:
        raise EncryptionError("Decryption key cannot be empty")

    try:
        fernet = Fernet(key.encode("ascii"))
        decrypted = fernet.decrypt(encrypted_text.encode("ascii"))
        _logger.info("Data decrypted successfully")
        return decrypted.decode("utf-8")
    except InvalidToken:
        _logger.error("Decryption failed: invalid key or corrupted data")
        raise EncryptionError("Decryption failed: invalid key or corrupted data")
    except Exception as exc:
        _logger.error("Decryption failed: %s", exc)
        raise EncryptionError(f"Decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2 fallback when bcrypt is not available)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random salt.

    The result is stored as ``salt:hash`` in hexadecimal format.

    Args:
        password: The plaintext password to hash.

    Returns:
        A string in format ``salt_hex:hash_hex``.

    Raises:
        EncryptionError: If hashing fails.
    """
    if not password:
        raise EncryptionError("Cannot hash empty password")

    try:
        salt = os.urandom(SALT_LENGTH)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=100_000,
        )
        _logger.info("Password hashed successfully")
        return f"{salt.hex()}:{key.hex()}"
    except Exception as exc:
        _logger.error("Password hashing failed: %s", exc)
        raise EncryptionError(f"Password hashing failed: {exc}") from exc


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash.

    Args:
        password: The plaintext password to verify.
        stored_hash: The stored hash in ``salt_hex:hash_hex`` format.

    Returns:
        True if the password matches, False otherwise.
    """
    if not password or not stored_hash:
        return False

    try:
        salt_hex, key_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)

        actual_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=100_000,
        )
        return secrets.compare_digest(actual_key, expected_key)
    except (ValueError, TypeError) as exc:
        _logger.error("Password verification failed: %s", exc)
        return False
