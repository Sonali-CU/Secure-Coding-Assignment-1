"""HMAC-SHA256 message authentication and a replay guard (Python standard library: hmac, hashlib).

* generate: a keyed tag proves the message came from someone holding the key and was not changed.
* verify:   compared in constant time with hmac.compare_digest, so the comparison time does not
            reveal how many leading characters matched.
* ReplayGuard: adds a nonce and timestamp inside the authenticated part, and remembers nonces, so
            an intercepted message cannot be submitted a second time.
"""
import hashlib
import hmac
import json
import secrets
import time

MIN_KEY_BYTES = 32   # HMAC key should be at least the hash output size


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("HMAC key must be bytes")
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"HMAC key must be at least {MIN_KEY_BYTES} bytes")


def generate(key: bytes, message: bytes) -> str:
    """Return the HMAC-SHA256 tag of message as lowercase hex (64 characters)."""
    _check_key(key)
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    return hmac.new(bytes(key), bytes(message), hashlib.sha256).hexdigest()


def verify(key: bytes, message: bytes, tag: str) -> bool:
    """True only if tag is the correct HMAC for message. Constant-time comparison."""
    _check_key(key)
    if not isinstance(message, (bytes, bytearray)) or not isinstance(tag, str):
        return False
    expected = generate(key, message)
    return hmac.compare_digest(expected.encode("ascii"), tag.strip().lower().encode("utf-8", "replace"))


def canonical(body: dict) -> bytes:
    """Stable byte encoding of a JSON object, so sender and receiver MAC the same bytes."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ReplayGuard:
    """Signs messages with {payload, nonce, timestamp} and rejects replays and stale messages."""

    def __init__(self, key: bytes, window_seconds: int = 60):
        _check_key(key)
        self._key = bytes(key)
        self._window = window_seconds
        self._seen = {}          # nonce -> time first seen

    def sign(self, payload: dict, timestamp: int | None = None) -> dict:
        body = {
            "payload": payload,
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time()) if timestamp is None else int(timestamp),
        }
        return {"body": body, "mac": generate(self._key, canonical(body))}

    def accept(self, message: dict) -> str:
        """Return 'ACCEPTED' or a 'REJECTED: <reason>' string."""
        try:
            body, mac = message["body"], message["mac"]
            nonce, timestamp = body["nonce"], int(body["timestamp"])
        except (KeyError, TypeError, ValueError):
            return "REJECTED: malformed message"
        if not verify(self._key, canonical(body), mac):
            return "REJECTED: MAC does not match (message modified or wrong key)"
        now = time.time()
        if abs(now - timestamp) > self._window:
            return "REJECTED: timestamp outside allowed window (stale or replayed later)"
        self._seen = {n: t for n, t in self._seen.items() if now - t <= self._window}
        if nonce in self._seen:
            return "REJECTED: replay (nonce already used)"
        self._seen[nonce] = now
        return "ACCEPTED"
