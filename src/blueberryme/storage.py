from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol

from .crypto import canonical_json, open_sealed, seal
from .errors import InfrastructureError


class StateBackend(Protocol):
    def put(self, kind: str, object_id: str, payload: bytes, expires_at: float | None = None) -> None: ...
    def get(self, kind: str, object_id: str) -> bytes | None: ...
    def delete(self, kind: str, object_id: str) -> None: ...
    def count(self, kind: str) -> int: ...
    def list_ids(self, kind: str) -> list[str]: ...
    def append_audit(self, payload: dict) -> None: ...
    def list_audit(self) -> list[dict]: ...
    def mark_consumed(self, intent_id: str) -> None: ...
    def is_consumed(self, intent_id: str) -> bool: ...


class MemoryStateBackend:
    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], tuple[bytes, float | None]] = {}
        self._audit: list[dict] = []
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    def put(self, kind: str, object_id: str, payload: bytes, expires_at: float | None = None) -> None:
        with self._lock:
            self._objects[(kind, object_id)] = (bytes(payload), expires_at)

    def get(self, kind: str, object_id: str) -> bytes | None:
        with self._lock:
            item = self._objects.get((kind, object_id))
            if item is None:
                return None
            payload, expires_at = item
            if expires_at is not None and time.time() >= expires_at:
                self._objects.pop((kind, object_id), None)
                return None
            return bytes(payload)

    def delete(self, kind: str, object_id: str) -> None:
        with self._lock:
            self._objects.pop((kind, object_id), None)

    def count(self, kind: str) -> int:
        with self._lock:
            now = time.time()
            expired = [key for key, (_, exp) in self._objects.items() if key[0] == kind and exp is not None and now >= exp]
            for key in expired:
                self._objects.pop(key, None)
            return sum(1 for key in self._objects if key[0] == kind)

    def list_ids(self, kind: str) -> list[str]:
        with self._lock:
            now = time.time()
            expired = [key for key, (_, exp) in self._objects.items() if key[0] == kind and exp is not None and now >= exp]
            for key in expired:
                self._objects.pop(key, None)
            return [object_id for (item_kind, object_id) in self._objects if item_kind == kind]

    def append_audit(self, payload: dict) -> None:
        with self._lock:
            self._audit.append(json.loads(json.dumps(payload)))

    def list_audit(self) -> list[dict]:
        with self._lock:
            return json.loads(json.dumps(self._audit))

    def mark_consumed(self, intent_id: str) -> None:
        with self._lock:
            self._consumed.add(intent_id)

    def is_consumed(self, intent_id: str) -> bool:
        with self._lock:
            return intent_id in self._consumed


class SQLiteStateBackend:
    """Small persistent reference backend.

    It is intentionally simple: one SQLite file is enough for v0.3 local/self-hosted
    deployments and tests. Enterprise HA stores are provider work, not protocol logic.
    Sensitive object payloads are encrypted by SecureState before they reach SQLite.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        try:
            with self._connect() as conn:
                conn.executescript(
                    """
                    PRAGMA journal_mode=WAL;
                    CREATE TABLE IF NOT EXISTS objects (
                        kind TEXT NOT NULL,
                        object_id TEXT NOT NULL,
                        payload BLOB NOT NULL,
                        expires_at REAL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (kind, object_id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_objects_kind ON objects(kind);
                    CREATE TABLE IF NOT EXISTS audit (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS consumed_intents (
                        intent_id TEXT PRIMARY KEY,
                        consumed_at REAL NOT NULL
                    );
                    """
                )
        except sqlite3.Error as exc:
            raise InfrastructureError("State backend unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def put(self, kind: str, object_id: str, payload: bytes, expires_at: float | None = None) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT INTO objects(kind, object_id, payload, expires_at, updated_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(kind, object_id) DO UPDATE SET payload=excluded.payload, expires_at=excluded.expires_at, updated_at=excluded.updated_at",
                    (kind, object_id, sqlite3.Binary(payload), expires_at, time.time()),
                )
        except sqlite3.Error as exc:
            raise InfrastructureError("State backend write failed") from exc

    def get(self, kind: str, object_id: str) -> bytes | None:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT payload, expires_at FROM objects WHERE kind=? AND object_id=?",
                    (kind, object_id),
                ).fetchone()
                if row is None:
                    return None
                payload, expires_at = row
                if expires_at is not None and time.time() >= float(expires_at):
                    conn.execute("DELETE FROM objects WHERE kind=? AND object_id=?", (kind, object_id))
                    return None
                return bytes(payload)
        except sqlite3.Error as exc:
            raise InfrastructureError("State backend read failed") from exc

    def delete(self, kind: str, object_id: str) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute("DELETE FROM objects WHERE kind=? AND object_id=?", (kind, object_id))
        except sqlite3.Error as exc:
            raise InfrastructureError("State backend delete failed") from exc

    def count(self, kind: str) -> int:
        try:
            with self._lock, self._connect() as conn:
                now = time.time()
                conn.execute("DELETE FROM objects WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))
                row = conn.execute("SELECT COUNT(*) FROM objects WHERE kind=?", (kind,)).fetchone()
                return int(row[0] if row else 0)
        except sqlite3.Error as exc:
            raise InfrastructureError("State backend count failed") from exc

    def list_ids(self, kind: str) -> list[str]:
        try:
            with self._lock, self._connect() as conn:
                now = time.time()
                conn.execute("DELETE FROM objects WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))
                rows = conn.execute("SELECT object_id FROM objects WHERE kind=? ORDER BY object_id", (kind,)).fetchall()
                return [str(row[0]) for row in rows]
        except sqlite3.Error as exc:
            raise InfrastructureError("State backend list failed") from exc

    def append_audit(self, payload: dict) -> None:
        try:
            raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            with self._lock, self._connect() as conn:
                conn.execute("INSERT INTO audit(payload) VALUES(?)", (raw,))
        except sqlite3.Error as exc:
            raise InfrastructureError("Audit write failed") from exc

    def list_audit(self) -> list[dict]:
        try:
            with self._lock, self._connect() as conn:
                rows = conn.execute("SELECT payload FROM audit ORDER BY seq").fetchall()
            return [json.loads(row[0]) for row in rows]
        except sqlite3.Error as exc:
            raise InfrastructureError("Audit read failed") from exc

    def mark_consumed(self, intent_id: str) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO consumed_intents(intent_id, consumed_at) VALUES(?,?)",
                    (intent_id, time.time()),
                )
        except sqlite3.Error as exc:
            raise InfrastructureError("Intent state write failed") from exc

    def is_consumed(self, intent_id: str) -> bool:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute("SELECT 1 FROM consumed_intents WHERE intent_id=?", (intent_id,)).fetchone()
                return row is not None
        except sqlite3.Error as exc:
            raise InfrastructureError("Intent state read failed") from exc


class SecureState:
    """Encrypts all internal state objects before they reach the backend."""

    def __init__(self, backend: StateBackend, key: bytes) -> None:
        self.backend = backend
        self.key = key

    @staticmethod
    def _aad(kind: str, object_id: str) -> bytes:
        return canonical_json({"protocol": "BBM/1", "kind": kind, "id": object_id})

    def put_json(self, kind: str, object_id: str, value: dict, expires_at: float | None = None) -> None:
        nonce, ciphertext = seal(self.key, canonical_json(value), aad=self._aad(kind, object_id))
        self.backend.put(kind, object_id, nonce + ciphertext, expires_at)

    def get_json(self, kind: str, object_id: str) -> dict | None:
        blob = self.backend.get(kind, object_id)
        if blob is None:
            return None
        if len(blob) < 13:
            raise InfrastructureError("Encrypted state is malformed")
        raw = open_sealed(self.key, blob[:12], blob[12:], aad=self._aad(kind, object_id))
        return json.loads(raw.decode("utf-8"))

    def delete(self, kind: str, object_id: str) -> None:
        self.backend.delete(kind, object_id)

    def count(self, kind: str) -> int:
        return self.backend.count(kind)

    def list_ids(self, kind: str) -> list[str]:
        return self.backend.list_ids(kind)
