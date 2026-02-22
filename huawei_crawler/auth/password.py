"""Password encoding helpers for the Huawei HG8145V5 router."""

import base64


def b64encode_password(password: str) -> str:
    """
    Replicate the router's  base64encode(Password.value)  from util.js.
    Standard RFC 4648 Base64 over the UTF-8 bytes of the password string.
    Used when CfgMode != 'DVODACOM2WIFI'.
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def pbkdf2_sha256_password(password: str, salt: str, iterations: int) -> str:
    """
    Replicate the loginWithSha256() function from index.asp (CfgMode DVODACOM2WIFI):

      1. PBKDF2(password, salt, {keySize:8, hasher:SHA256, iterations:N})
         → 32 bytes (keySize 8 = 8 × 32-bit words)
      2. CryptoJS.SHA256(pbkdf2.toString())  where .toString() gives hex
         → SHA-256 over the UTF-8 bytes of the PBKDF2 hex string
      3. Base64(sha256_hex.encode('utf-8'))  – CryptoJS Utf8.parse + Base64.stringify
    """
    import hashlib as _hashlib
    dk = _hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=32,   # keySize:8 means 8 * 32-bit words = 32 bytes
    )
    pbkdf2_hex = dk.hex()                                     # step 1 → hex string
    sha256_hex = _hashlib.sha256(pbkdf2_hex.encode("utf-8")).hexdigest()  # step 2
    return base64.b64encode(sha256_hex.encode("utf-8")).decode("ascii")   # step 3
