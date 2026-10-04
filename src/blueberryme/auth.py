from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Principal:
    """Authenticated caller of the HTTP gateway.

    `agent_id` is optional. A key bound to an agent can only act as that agent and only
    sees jobs submitted by it. A key without `agent_id` is a tenant-level service key.
    """

    tenant_id: str
    purposes: frozenset[str]
    agent_id: str | None = None

    def allows_purpose(self, purpose: str) -> bool:
        return purpose in self.purposes or "*" in self.purposes


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Return (key, sha256). Only the hash belongs in the key file."""
    key = "bbm_" + secrets.token_urlsafe(32)
    return key, hash_api_key(key)


class ApiKeyRegistry:
    """Maps SHA-256 hashes of API keys to principals.

    Plaintext keys are never stored. Keys are 256-bit random values, so looking up the
    hash in a dict does not give a useful timing signal.
    """

    def __init__(self, keys: Mapping[str, Principal]) -> None:
        for digest in keys:
            if not _SHA256_HEX.fullmatch(digest):
                raise ValueError("API key registry entries must be lowercase SHA-256 hex digests")
        self._keys = dict(keys)

    def __len__(self) -> int:
        return len(self._keys)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ApiKeyRegistry":
        entries = raw.get("keys")
        if not isinstance(entries, list) or not entries:
            raise ValueError("API key file must contain a non-empty 'keys' list")
        keys: dict[str, Principal] = {}
        for item in entries:
            if not isinstance(item, Mapping):
                raise ValueError("Each API key entry must be a mapping")
            digest = str(item.get("sha256", "")).strip().lower()
            tenant = str(item.get("tenant_id", "")).strip()
            purposes = item.get("purposes")
            agent = item.get("agent_id")
            if not _SHA256_HEX.fullmatch(digest):
                raise ValueError("API key entry needs 'sha256' (64 hex characters)")
            if not tenant:
                raise ValueError("API key entry needs 'tenant_id'")
            if not isinstance(purposes, list) or not purposes:
                raise ValueError("API key entry needs a non-empty 'purposes' list")
            if digest in keys:
                raise ValueError("Duplicate API key hash in key file")
            keys[digest] = Principal(
                tenant_id=tenant,
                purposes=frozenset(str(p) for p in purposes),
                agent_id=str(agent).strip() if agent else None,
            )
        return cls(keys)

    @classmethod
    def from_file(cls, path: str | Path) -> "ApiKeyRegistry":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, Mapping):
            raise ValueError("API key file must be a YAML mapping")
        return cls.from_mapping(raw)

    def authenticate(self, presented: str | None) -> Principal | None:
        if not presented:
            return None
        return self._keys.get(hash_api_key(presented))
