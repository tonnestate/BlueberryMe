from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from .crypto import derive_key


def _decode_env_key(value: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise ValueError("BBM_MASTER_KEY_B64 is not valid base64") from exc
    if len(raw) != 32:
        raise ValueError("BBM_MASTER_KEY_B64 must decode to exactly 32 bytes")
    return raw


def load_or_create_master_key(state_dir: str | Path) -> bytes:
    env = os.environ.get("BBM_MASTER_KEY_B64")
    if env:
        return _decode_env_key(env.strip())

    explicit = os.environ.get("BBM_MASTER_KEY_FILE")
    path = Path(explicit) if explicit else Path(state_dir) / "master.key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = path.read_bytes()
        if len(raw) != 32:
            raise ValueError("BlueberryMe master key file must contain exactly 32 bytes")
        return raw

    raw = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise
    return raw


def subkeys(master_key: bytes) -> dict[str, bytes]:
    return {
        "state": derive_key(master_key, "state"),
        "intent": derive_key(master_key, "intent"),
        "audit": derive_key(master_key, "audit"),
    }
