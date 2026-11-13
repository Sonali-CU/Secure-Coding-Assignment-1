"""Password hashing and verification with Argon2id (argon2-cffi).

Argon2id is the OWASP-recommended password hash: it is salted and memory-hard, so guessing
attacks cost memory as well as CPU. The salt is generated randomly for every hash and stored
inside the returned string, so no separate salt column is needed.
"""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Parameters follow OWASP guidance (memory 64 MiB, 3 iterations, 4 lanes). Tune for your hardware.
HASHER = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32, salt_len=16)
MAX_PASSWORD_BYTES = 1024    # refuse absurdly long input before spending memory on it


def hash_password(password: str) -> str:
    """Return an Argon2id hash string such as '$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>'."""
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    if not password:
        raise ValueError("password must not be empty")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError("password is too long")
    return HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """True only if the password matches. Never raises for wrong passwords or malformed hashes."""
    if not isinstance(stored_hash, str) or not isinstance(password, str) or not password:
        return False
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    try:
        return HASHER.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the stored hash was made with weaker parameters and should be upgraded at next login."""
    try:
        return HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
