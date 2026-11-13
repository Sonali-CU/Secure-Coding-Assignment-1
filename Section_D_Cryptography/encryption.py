"""AES-256-GCM authenticated encryption (cryptography library).

Format of an encrypted blob:   nonce (12 bytes) || ciphertext || tag (16 bytes)

* A fresh random 96-bit nonce is generated for EVERY encryption. A nonce must never be reused with
  the same key, because reuse breaks GCM's confidentiality and authenticity guarantees.
* GCM authenticates the ciphertext: any modification of the nonce, ciphertext, tag or the
  associated data makes decryption fail. Nothing is returned for a tampered message.
* Associated data (AAD) is authenticated but not encrypted. Binding it to a record ID (for example
  'customer:42') stops a valid ciphertext being moved to another record.

No custom cipher or mode is implemented here: all cryptography comes from the 'cryptography' library.
"""
import base64
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32        # AES-256
NONCE_SIZE = 12      # 96-bit nonce, the size recommended for GCM
TAG_SIZE = 16        # 128-bit authentication tag


class CryptoError(Exception):
    """Base class for errors raised by this package."""


class DecryptionError(CryptoError):
    """Raised when authentication fails. The message is deliberately generic."""


def generate_key() -> bytes:
    """Return a new 256-bit key from the operating system's CSPRNG."""
    return secrets.token_bytes(KEY_SIZE)


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes")
    if len(key) != KEY_SIZE:
        # Do not include the key or its length-specific details in the message.
        raise ValueError(f"AES-256 key must be exactly {KEY_SIZE} bytes")


def _check_aad(associated_data):
    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError("associated_data must be bytes or None")


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Encrypt and authenticate plaintext. Returns nonce || ciphertext || tag."""
    _check_key(key)
    _check_aad(associated_data)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    nonce = os.urandom(NONCE_SIZE)                    # fresh nonce for every call
    ciphertext_and_tag = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), associated_data)
    return nonce + ciphertext_and_tag


def decrypt(key: bytes, blob: bytes, associated_data: bytes | None = None) -> bytes:
    """Verify and decrypt a blob produced by encrypt(). Raises DecryptionError on any failure."""
    _check_key(key)
    _check_aad(associated_data)
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("Authentication failed: data is malformed.")
    nonce, ciphertext_and_tag = bytes(blob[:NONCE_SIZE]), bytes(blob[NONCE_SIZE:])
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext_and_tag, associated_data)
    except InvalidTag:
        raise DecryptionError(
            "Authentication failed: wrong key, wrong associated data, or the data was modified."
        ) from None


def encrypt_text(key: bytes, text: str, associated_data: str | None = None) -> str:
    """Convenience wrapper: UTF-8 text in, base64 text out (suitable for storing in a database column)."""
    aad = associated_data.encode("utf-8") if associated_data is not None else None
    return base64.b64encode(encrypt(key, text.encode("utf-8"), aad)).decode("ascii")


def decrypt_text(key: bytes, token: str, associated_data: str | None = None) -> str:
    aad = associated_data.encode("utf-8") if associated_data is not None else None
    try:
        blob = base64.b64decode(token, validate=True)
    except (ValueError, TypeError):
        raise DecryptionError("Authentication failed: data is not valid base64.") from None
    return decrypt(key, blob, aad).decode("utf-8")
