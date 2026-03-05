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


# ---------------------------------------------------------------------------
# LMSA AES-128-CBC encryption (from Software Fix.exe.config)
# ---------------------------------------------------------------------------
# Confirmed from decompiled LMSA 7.5.4.2 assemblies:
#   AESKey = "jdkei3ffkjijut46#$%6y7U8km4p<mdT"  (first 16 bytes → AES-128)
#   AESIV  = "52,*u^yhNjk<./O0"
#
# Used to decrypt firmware metadata from getNewResource.jhtml (the `data`
# field may be AES-encrypted) and to encrypt data sent to the server.
# ---------------------------------------------------------------------------

LMSA_AES_KEY: bytes = b"jdkei3ffkjijut46#$%6y7U8km4p<mdT"[:16]
LMSA_AES_IV: bytes = b"52,*u^yhNjk<./O0"

# Optional dependency: pycryptodome (for AES)
try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad, unpad as _unpad
    _PYCRYPTO_AVAILABLE = True
except ImportError:
    _PYCRYPTO_AVAILABLE = False


def lmsa_aes_decrypt(ciphertext_b64: str) -> str:
    """AES-128-CBC decrypt a Base64-encoded ciphertext from LMSA server.

    Used to decrypt ROM download links and firmware metadata returned by
    ``getNewResource.jhtml``. Matches lmsa.py ``aes_decrypt()`` exactly.

    Args:
        ciphertext_b64: Base64-encoded AES-128-CBC ciphertext.

    Returns:
        Decrypted UTF-8 plaintext string.

    Raises:
        EncryptionError: If decryption fails or pycryptodome is not installed.
    """
    if not _PYCRYPTO_AVAILABLE:
        raise EncryptionError(
            "pycryptodome required for AES decryption: pip install pycryptodome"
        )
    try:
        raw = base64.b64decode(ciphertext_b64)
        cipher = _AES.new(LMSA_AES_KEY, _AES.MODE_CBC, LMSA_AES_IV)
        decrypted = _unpad(cipher.decrypt(raw), _AES.block_size)
        return decrypted.decode("utf-8")
    except Exception as exc:
        _logger.error("LMSA AES decryption failed: %s", exc)
        raise EncryptionError(f"LMSA AES decryption failed: {exc}") from exc


def lmsa_aes_encrypt(plaintext: str) -> str:
    """AES-128-CBC encrypt plaintext for LMSA server.

    Matches lmsa.py ``aes_encrypt()`` exactly.

    Args:
        plaintext: UTF-8 plaintext string to encrypt.

    Returns:
        Base64-encoded ciphertext string.

    Raises:
        EncryptionError: If encryption fails or pycryptodome is not installed.
    """
    if not _PYCRYPTO_AVAILABLE:
        raise EncryptionError(
            "pycryptodome required for AES encryption: pip install pycryptodome"
        )
    try:
        cipher = _AES.new(LMSA_AES_KEY, _AES.MODE_CBC, LMSA_AES_IV)
        padded = _pad(plaintext.encode("utf-8"), _AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode("ascii")
    except Exception as exc:
        _logger.error("LMSA AES encryption failed: %s", exc)
        raise EncryptionError(f"LMSA AES encryption failed: {exc}") from exc


def lmsa_try_decrypt_data(data_value: str) -> str:
    """Try to AES-decrypt a data field; return as-is if not encrypted.

    The ``data`` field in LMSA API responses may be:
    - A plain JSON string (not encrypted)
    - An AES-128-CBC encrypted Base64 string

    This function tries decryption first; if it fails (not valid Base64 or
    not valid AES padding), it returns the original string unchanged.

    Args:
        data_value: The raw `data` field value from an API response.

    Returns:
        Decrypted string if it was encrypted, or original string otherwise.
    """
    if not data_value or not isinstance(data_value, str):
        return data_value
    try:
        return lmsa_aes_decrypt(data_value)
    except (EncryptionError, Exception):
        return data_value
