"""Secure key generation, storage and management.

Where keys come from, in order:
  1. Environment variable <NAME>_KEY_B64 (base64 key injected by a secrets manager or CI secret store).
  2. A key file in KEY_DIR (default: ./secure_keys), created with the OS CSPRNG on first use.

Rules enforced here:
  * Keys are never hard-coded and never printed or logged (only metadata is shown).
  * Key files are created exclusively (O_EXCL) with owner-only permissions (0600 on POSIX).
  * On POSIX, a key file that is readable by group or others is refused.
  * Keys are rotated by archiving the old key (kept only to decrypt old data) and creating a new one.

Windows note: NTFS ignores POSIX mode bits. On Windows, protect the key folder with an ACL that
allows only your user account (see README). This module cannot enforce that itself.
"""
import base64
import binascii
import os
import secrets
import stat
import time
from pathlib import Path

DEFAULT_KEY_DIR = Path(os.environ.get("KEY_DIR", Path(__file__).resolve().parent / "secure_keys"))
KEY_BYTES = 32
IS_POSIX = os.name == "posix"


class KeyManagementError(Exception):
    pass


class KeyStore:
    def __init__(self, directory: str | Path | None = None):
        self.directory = Path(directory) if directory else DEFAULT_KEY_DIR

    def _path(self, name: str) -> Path:
        if not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("key name may contain only letters, digits, '-' and '_'")
        return self.directory / f"{name}.key"

    def get_key(self, name: str, size: int = KEY_BYTES) -> bytes:
        """Return the key called `name`, creating it on first use."""
        env_value = os.environ.get(f"{name.upper()}_KEY_B64")
        if env_value:
            return self._from_env(name, env_value, size)

        path = self._path(name)
        if path.exists():
            return self._read_file(path, size)
        return self._create_file(path, size)

    def _from_env(self, name, value, size):
        try:
            key = base64.b64decode(value.strip(), validate=True)
        except (binascii.Error, ValueError):
            raise KeyManagementError(f"{name.upper()}_KEY_B64 is not valid base64") from None
        if len(key) != size:
            raise KeyManagementError(f"{name.upper()}_KEY_B64 must decode to {size} bytes")
        return key

    def _read_file(self, path: Path, size: int) -> bytes:
        if IS_POSIX:
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise KeyManagementError(
                    f"{path.name} is accessible to other users (mode {oct(mode)}). Run: chmod 600 {path}")
        key = path.read_bytes()
        if len(key) != size:
            raise KeyManagementError(f"{path.name} has an invalid length")
        return key

    def _create_file(self, path: Path, size: int) -> bytes:
        self.directory.mkdir(parents=True, exist_ok=True)
        if IS_POSIX:
            os.chmod(self.directory, 0o700)
        key = secrets.token_bytes(size)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)               # fails if the file already exists
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        return key

    def rotate(self, name: str, size: int = KEY_BYTES) -> bytes:
        """Archive the current key as <name>.<timestamp>.old and create a new one."""
        path = self._path(name)
        if path.exists():
            archive = path.with_name(f"{name}.{int(time.time())}.old")
            path.rename(archive)
        return self._create_file(path, size)

    def describe(self, name: str) -> dict:
        """Metadata only: never returns key material."""
        path = self._path(name)
        info = {"name": name, "file": str(path), "env_override": f"{name.upper()}_KEY_B64" in os.environ}
        if path.exists():
            info["size_bits"] = path.stat().st_size * 8
            info["permissions"] = oct(stat.S_IMODE(path.stat().st_mode)) if IS_POSIX else "ACL (see README)"
        else:
            info["size_bits"] = None
            info["permissions"] = None
        return info
