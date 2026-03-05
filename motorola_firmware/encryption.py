"""
Encryption utilities using AES-256-GCM and bcrypt hashing.
"""

from __future__ import annotations

import base64
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.bcrypt import BCryptKDF

from motorola_firmware.logger import get_logger

_LOGGER = get_logger(__name__)
_BACKEND = default_backend()
_AES_KEY_BYTES = 32
_GCM_IV_BYTES = 12
_GCM_TAG_BYTES = 16


def generate_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(_AES_KEY_BYTES)


def _build_cipher(key: bytes, iv: bytes) -> Cipher:
    return Cipher(algorithms.AES(key), modes.GCM(iv), backend=_BACKEND)


def encrypt(text: str, key: bytes) -> str:
    """Encrypt text with AES-256-GCM.

    Args:
        text: Plaintext to encrypt.
        key: 32-byte AES key.

    Returns:
        Base64-encoded ciphertext including IV and tag.
    """
    iv = os.urandom(_GCM_IV_BYTES)
    cipher = _build_cipher(key, iv)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode("utf-8")) + encryptor.finalize()
    payload = iv + encryptor.tag + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt(encrypted_text: str, key: bytes) -> str:
    """Decrypt AES-256-GCM encrypted payload."""
    try:
        payload = base64.b64decode(encrypted_text.encode("ascii"))
        iv, tag, ciphertext = _split_payload(payload)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=_BACKEND,
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        _LOGGER.error("Failed to decrypt value: %s", exc)
        raise


def _split_payload(payload: bytes) -> Tuple[bytes, bytes, bytes]:
    if len(payload) < (_GCM_IV_BYTES + _GCM_TAG_BYTES):
        raise ValueError("Encrypted payload is too short")
    iv = payload[:_GCM_IV_BYTES]
    tag = payload[_GCM_IV_BYTES:_GCM_IV_BYTES + _GCM_TAG_BYTES]
    ciphertext = payload[_GCM_IV_BYTES + _GCM_TAG_BYTES :]
    return iv, tag, ciphertext


def hash_password(password: str) -> str:
    """Hash a password using bcrypt KDF."""
    salt = os.urandom(16)
    kdf = BCryptKDF(
        salt=salt,
        length=32,
        rounds=12,
        backend=_BACKEND,
    )
    derived = kdf.derive(password.encode("utf-8"))
    return base64.b64encode(salt + derived).decode("ascii")
