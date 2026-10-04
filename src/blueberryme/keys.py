from __future__ import annotations

import base64
import os
import secrets
import stat
import warnings
from pathlib import Path

from .crypto import derive_key

DEV_MODE_ENV = "BBM_DEV_MODE"
KEY_B64_ENV = "BBM_MASTER_KEY_B64"
KEY_FILE_ENV = "BBM_MASTER_KEY_FILE"


class MasterKeyError(ValueError):
    """Master key material is missing or configured unsafely. Raised at startup only."""


def dev_mode_enabled() -> bool:
    return os.environ.get(DEV_MODE_ENV, "").strip().lower() in {"1", "true", "yes"}


def _decode_env_key(value: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise MasterKeyError(f"{KEY_B64_ENV} is not valid base64") from exc
    if len(raw) != 32:
        raise MasterKeyError(f"{KEY_B64_ENV} must decode to exactly 32 bytes")
    return raw


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _read_key_file(path: Path) -> bytes:
    raw = path.read_bytes()
    if len(raw) != 32:
        raise MasterKeyError("BlueberryMe master key file must contain exactly 32 bytes")
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            warnings.warn(
                f"BlueberryMe master key file {path} is readable by group/others (mode {mode:o}); use chmod 600",
                stacklevel=3,
            )
    return raw


def write_master_key_file(path: str | Path) -> Path:
    """Create a new 32-byte key file with mode 0600. Refuses to overwrite."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_bytes(32)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    except Exception:
        try:
            target.unlink(missing_ok=True)
        finally:
            raise
    return target


def load_or_create_master_key(state_dir: str | Path) -> bytes:
    """Resolve the master key for a persistent runtime.

    Order:
    1. BBM_MASTER_KEY_B64 (32 bytes, base64/base64url).
    2. BBM_MASTER_KEY_FILE, which must exist and lie outside the state directory.
    3. Only with BBM_DEV_MODE=1: <state_dir>/master.key, created on first use.

    Without dev mode, a key stored next to the encrypted state is refused: anyone who
    copies the state directory would otherwise hold both ciphertext and key.
    """
    env = os.environ.get(KEY_B64_ENV)
    if env:
        return _decode_env_key(env.strip())

    dev = dev_mode_enabled()
    state = Path(state_dir).expanduser().resolve()
    explicit = os.environ.get(KEY_FILE_ENV)

    if explicit:
        path = Path(explicit).expanduser().resolve()
        if _is_within(path, state) and not dev:
            raise MasterKeyError(
                f"{KEY_FILE_ENV} points inside the state directory {state}. "
                "Store the key outside the state directory, or set BBM_DEV_MODE=1 for local development."
            )
        if path.exists():
            return _read_key_file(path)
        if not dev:
            raise MasterKeyError(
                f"Master key file {path} does not exist. Create it with `blueberryme keygen {path}`."
            )
        write_master_key_file(path)
        return _read_key_file(path)

    if not dev:
        raise MasterKeyError(
            "No master key configured. Set BBM_MASTER_KEY_B64, or BBM_MASTER_KEY_FILE pointing to a key "
            "outside the state directory (create one with `blueberryme keygen <path>`). "
            "For local development only, set BBM_DEV_MODE=1 to auto-create <state_dir>/master.key."
        )

    path = state / "master.key"
    if path.exists():
        return _read_key_file(path)
    write_master_key_file(path)
    return _read_key_file(path)


def subkeys(master_key: bytes) -> dict[str, bytes]:
    return {
        "state": derive_key(master_key, "state"),
        "intent": derive_key(master_key, "intent"),
        "audit": derive_key(master_key, "audit"),
    }
