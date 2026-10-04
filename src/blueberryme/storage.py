from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Protocol

from .crypto import canonical_json, open_sealed, seal
from .errors import InfrastructureError

# Consumed intents only need to be remembered while the intent itself could still be
# valid. Resolution intents live <= 300 s, job intents <= 24 h. Anything consumed
# longer ago than this window is rejected by its own expiry check anyway.
CONSUMED_RETENTION_SECONDS = 25 * 3600


class StateBackend(Protocol):
    """Storage contract for the BlueberryMe privacy boundary.

    ``consume_once`` and ``try_claim`` MUST be atomic across every process that
    shares the backend. They are the replay and double-execution guards.
    """

    def put(
        self, kind: str, object_id: str, payload: bytes, expires_at: float | None = None, owner: str | None = None
    ) -> None: ...
    def get(self, kind: str, object_id: str) -> bytes | None: ...
    def delete(self, kind: str, object_id: str) -> None: ...
    def delete_owned(self, owner: str) -> int: ...
    def count(self, kind: str) -> int: ...
    def list_ids(self, kind: str) -> list[str]: ...
    def append_audit(self, payload: dict) -> None: ...
    def list_audit(self) -> list[dict]: ...
    def consume_once(self, token_id: str) -> bool: ...
    def is_consumed(self, token_id: str) -> bool: ...
    def mark_consumed(self, token_id: str) -> None: ...
    def try_claim(self, name: str, holder: str, ttl_seconds: float) -> bool: ...
    def release_claim(self, name: str, holder: str) -> None: ...
    def purge_expired(self) -> None: ...
    def transaction(self) -> Iterator[None]: ...


class MemoryStateBackend:
    """In-process backend for tests and single-process embedding."""

    def __init__(self) -> None:
        # (kind, id) -> (payload, expires_at, owner)
        self._objects: dict[tuple[str, str], tuple[bytes, float | None, str | None]] = {}
        self._owners: dict[str, set[tuple[str, str]]] = {}
        self._audit: list[dict] = []
        self._consumed: dict[str, float] = {}
        self._claims: dict[str, tuple[str, float]] = {}
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    def _drop(self, key: tuple[str, str]) -> None:
        item = self._objects.pop(key, None)
        if item is not None and item[2] is not None:
            owned = self._owners.get(item[2])
            if owned is not None:
                owned.discard(key)
                if not owned:
                    self._owners.pop(item[2], None)

    def put(
        self, kind: str, object_id: str, payload: bytes, expires_at: float | None = None, owner: str | None = None
    ) -> None:
        with self._lock:
            key = (kind, object_id)
            self._drop(key)
            self._objects[key] = (bytes(payload), expires_at, owner)
            if owner is not None:
                self._owners.setdefault(owner, set()).add(key)

    def get(self, kind: str, object_id: str) -> bytes | None:
        with self._lock:
            item = self._objects.get((kind, object_id))
            if item is None:
                return None
            payload, expires_at, _ = item
            if expires_at is not None and time.time() >= expires_at:
                self._drop((kind, object_id))
                return None
            return bytes(payload)

    def delete(self, kind: str, object_id: str) -> None:
        with self._lock:
            self._drop((kind, object_id))

    def delete_owned(self, owner: str) -> int:
        with self._lock:
            keys = list(self._owners.pop(owner, set()))
            for key in keys:
                self._objects.pop(key, None)
            return len(keys)

    def _purge_kind(self, kind: str) -> None:
        now = time.time()
        expired = [k for k, (_, exp, _) in self._objects.items() if k[0] == kind and exp is not None and now >= exp]
        for key in expired:
            self._drop(key)

    def count(self, kind: str) -> int:
        with self._lock:
            self._purge_kind(kind)
            return sum(1 for key in self._objects if key[0] == kind)

    def list_ids(self, kind: str) -> list[str]:
        with self._lock:
            self._purge_kind(kind)
            return sorted(object_id for (item_kind, object_id) in self._objects if item_kind == kind)

    def append_audit(self, payload: dict) -> None:
        with self._lock:
            self._audit.append(json.loads(json.dumps(payload)))

    def list_audit(self) -> list[dict]:
        with self._lock:
            return json.loads(json.dumps(self._audit))

    def consume_once(self, token_id: str) -> bool:
        with self._lock:
            if token_id in self._consumed:
                return False
            self._consumed[token_id] = time.time()
            return True

    def is_consumed(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._consumed

    def mark_consumed(self, token_id: str) -> None:
        self.consume_once(token_id)

    def try_claim(self, name: str, holder: str, ttl_seconds: float) -> bool:
        with self._lock:
            now = time.time()
            current = self._claims.get(name)
            if current is not None and current[1] > now and current[0] != holder:
                return False
            self._claims[name] = (holder, now + ttl_seconds)
            return True

    def release_claim(self, name: str, holder: str) -> None:
        with self._lock:
            current = self._claims.get(name)
            if current is not None and current[0] == holder:
                self._claims.pop(name, None)

    def purge_expired(self) -> None:
        with self._lock:
            now = time.time()
            for key in [k for k, (_, exp, _) in self._objects.items() if exp is not None and now >= exp]:
                self._drop(key)
            cutoff = now - CONSUMED_RETENTION_SECONDS
            self._consumed = {k: v for k, v in self._consumed.items() if v >= cutoff}
            self._claims = {k: v for k, v in self._claims.items() if v[1] > now}


class SQLiteStateBackend:
    """Small persistent reference backend.

    One SQLite file is enough for local/self-hosted deployments and tests. Several
    processes may share the file: replay protection (``consume_once``) and job claims
    (``try_claim``) are atomic at the database level, not only inside one process.
    Sensitive object payloads are encrypted by ``SecureState`` before they get here.
    Enterprise HA stores are provider work, not protocol logic.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._depth = 0
        self._ops = 0
        try:
            self._conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.executescript(
                """
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
                CREATE TABLE IF NOT EXISTS claims (
                    name TEXT PRIMARY KEY,
                    holder TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            columns = {row[1] for row in self._conn.execute("PRAGMA table_info(objects)")}
            if "owner" not in columns:
                # v0.3.0 -> v0.3.1 migration. Existing rows keep owner NULL.
                self._conn.execute("ALTER TABLE objects ADD COLUMN owner TEXT")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_objects_owner ON objects(owner)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_objects_expiry ON objects(expires_at)")
        except sqlite3.Error as exc:
            raise InfrastructureError("State backend unavailable") from exc

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Group many writes into one atomic, single-fsync commit. Nestable."""
        with self._lock:
            outer = self._depth == 0
            try:
                if outer:
                    self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise InfrastructureError("State backend transaction failed") from exc
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if outer:
                    try:
                        self._conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise
            self._depth -= 1
            if outer:
                try:
                    self._conn.execute("COMMIT")
                except sqlite3.Error as exc:
                    raise InfrastructureError("State backend commit failed") from exc

    def _exec(self, sql: str, params: tuple = (), *, error: str) -> sqlite3.Cursor:
        try:
            with self._lock:
                return self._conn.execute(sql, params)
        except sqlite3.Error as exc:
            raise InfrastructureError(error) from exc

    def put(
        self, kind: str, object_id: str, payload: bytes, expires_at: float | None = None, owner: str | None = None
    ) -> None:
        self._exec(
            "INSERT INTO objects(kind, object_id, payload, expires_at, updated_at, owner) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(kind, object_id) DO UPDATE SET payload=excluded.payload, expires_at=excluded.expires_at, "
            "updated_at=excluded.updated_at, owner=excluded.owner",
            (kind, object_id, sqlite3.Binary(payload), expires_at, time.time(), owner),
            error="State backend write failed",
        )

    def get(self, kind: str, object_id: str) -> bytes | None:
        with self._lock:
            row = self._exec(
                "SELECT payload, expires_at FROM objects WHERE kind=? AND object_id=?",
                (kind, object_id),
                error="State backend read failed",
            ).fetchone()
            if row is None:
                return None
            payload, expires_at = row
            if expires_at is not None and time.time() >= float(expires_at):
                self._exec(
                    "DELETE FROM objects WHERE kind=? AND object_id=?", (kind, object_id), error="State backend delete failed"
                )
                return None
            return bytes(payload)

    def delete(self, kind: str, object_id: str) -> None:
        self._exec("DELETE FROM objects WHERE kind=? AND object_id=?", (kind, object_id), error="State backend delete failed")

    def delete_owned(self, owner: str) -> int:
        cur = self._exec("DELETE FROM objects WHERE owner=?", (owner,), error="State backend delete failed")
        return int(cur.rowcount or 0)

    def count(self, kind: str) -> int:
        row = self._exec(
            "SELECT COUNT(*) FROM objects WHERE kind=? AND (expires_at IS NULL OR expires_at > ?)",
            (kind, time.time()),
            error="State backend count failed",
        ).fetchone()
        return int(row[0] if row else 0)

    def list_ids(self, kind: str) -> list[str]:
        rows = self._exec(
            "SELECT object_id FROM objects WHERE kind=? AND (expires_at IS NULL OR expires_at > ?) ORDER BY object_id",
            (kind, time.time()),
            error="State backend list failed",
        ).fetchall()
        return [str(row[0]) for row in rows]

    def append_audit(self, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self._exec("INSERT INTO audit(payload) VALUES(?)", (raw,), error="Audit write failed")

    def list_audit(self) -> list[dict]:
        rows = self._exec("SELECT payload FROM audit ORDER BY seq", error="Audit read failed").fetchall()
        return [json.loads(row[0]) for row in rows]

    def consume_once(self, token_id: str) -> bool:
        with self._lock:
            cur = self._exec(
                "INSERT OR IGNORE INTO consumed_intents(intent_id, consumed_at) VALUES(?,?)",
                (token_id, time.time()),
                error="Intent state write failed",
            )
            first = cur.rowcount == 1
            self._ops += 1
            if self._ops % 1000 == 0:
                self._exec(
                    "DELETE FROM consumed_intents WHERE consumed_at < ?",
                    (time.time() - CONSUMED_RETENTION_SECONDS,),
                    error="Intent state purge failed",
                )
            return first

    def is_consumed(self, token_id: str) -> bool:
        row = self._exec(
            "SELECT 1 FROM consumed_intents WHERE intent_id=?", (token_id,), error="Intent state read failed"
        ).fetchone()
        return row is not None

    def mark_consumed(self, token_id: str) -> None:
        self.consume_once(token_id)

    def try_claim(self, name: str, holder: str, ttl_seconds: float) -> bool:
        now = time.time()
        with self._lock, self.transaction():
            self._exec(
                "INSERT INTO claims(name, holder, expires_at) VALUES(?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET holder=excluded.holder, expires_at=excluded.expires_at "
                "WHERE claims.expires_at <= ? OR claims.holder = excluded.holder",
                (name, holder, now + ttl_seconds, now),
                error="Claim write failed",
            )
            row = self._exec("SELECT holder FROM claims WHERE name=?", (name,), error="Claim read failed").fetchone()
            return row is not None and row[0] == holder

    def release_claim(self, name: str, holder: str) -> None:
        self._exec("DELETE FROM claims WHERE name=? AND holder=?", (name, holder), error="Claim release failed")

    def purge_expired(self) -> None:
        now = time.time()
        with self.transaction():
            self._exec(
                "DELETE FROM objects WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,), error="Purge failed"
            )
            self._exec("DELETE FROM claims WHERE expires_at <= ?", (now,), error="Purge failed")
            self._exec(
                "DELETE FROM consumed_intents WHERE consumed_at < ?", (now - CONSUMED_RETENTION_SECONDS,), error="Purge failed"
            )


class SecureState:
    """Encrypts all internal state objects before they reach the backend."""

    def __init__(self, backend: StateBackend, key: bytes) -> None:
        self.backend = backend
        self.key = key

    @staticmethod
    def _aad(kind: str, object_id: str) -> bytes:
        return canonical_json({"protocol": "BBM/1", "kind": kind, "id": object_id})

    def put_json(
        self, kind: str, object_id: str, value: dict, expires_at: float | None = None, owner: str | None = None
    ) -> None:
        nonce, ciphertext = seal(self.key, canonical_json(value), aad=self._aad(kind, object_id))
        self.backend.put(kind, object_id, nonce + ciphertext, expires_at, owner)

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

    def delete_owned(self, owner: str) -> int:
        return self.backend.delete_owned(owner)

    def count(self, kind: str) -> int:
        return self.backend.count(kind)

    def list_ids(self, kind: str) -> list[str]:
        return self.backend.list_ids(kind)

    def transaction(self):
        return self.backend.transaction()
