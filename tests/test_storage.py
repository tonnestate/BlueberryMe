import sqlite3
import time
from pathlib import Path

from blueberryme.models import DataClass
from blueberryme.policy import load_policy
from blueberryme.runtime import BlueberryRuntime
from blueberryme.storage import MemoryStateBackend, SQLiteStateBackend

POLICY = Path(__file__).parents[1] / "policies" / "eu-business.yaml"


def _backends(tmp_path):
    return [MemoryStateBackend(), SQLiteStateBackend(tmp_path / "s.db")]


def test_consume_once_is_first_writer_wins(tmp_path):
    for backend in _backends(tmp_path):
        assert backend.consume_once("i1") is True
        assert backend.consume_once("i1") is False
        assert backend.is_consumed("i1")


def test_claims_exclude_until_expiry(tmp_path):
    for backend in _backends(tmp_path):
        assert backend.try_claim("job", "w1", 0.05)
        assert not backend.try_claim("job", "w2", 10)
        assert backend.try_claim("job", "w1", 10)  # holder may extend
        backend.release_claim("job", "w1")
        assert backend.try_claim("job", "w2", 0.05)
        time.sleep(0.08)
        assert backend.try_claim("job", "w3", 10)


def test_delete_owned_only_touches_owner(tmp_path):
    for backend in _backends(tmp_path):
        backend.put("handle", "h1", b"x", owner="L1")
        backend.put("handle", "h2", b"x", owner="L1")
        backend.put("handle", "h3", b"x", owner="L2")
        backend.put("lease", "L1", b"x")
        assert backend.delete_owned("L1") == 2
        assert backend.get("handle", "h3") == b"x"
        assert backend.get("lease", "L1") == b"x"


def test_sqlite_transaction_rolls_back(tmp_path):
    backend = SQLiteStateBackend(tmp_path / "s.db")
    try:
        with backend.transaction():
            backend.put("k", "1", b"x")
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert backend.get("k", "1") is None


def test_v030_database_is_migrated(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE objects (kind TEXT NOT NULL, object_id TEXT NOT NULL, payload BLOB NOT NULL,
            expires_at REAL, updated_at REAL NOT NULL, PRIMARY KEY (kind, object_id));
        CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
        CREATE TABLE consumed_intents (intent_id TEXT PRIMARY KEY, consumed_at REAL NOT NULL);
        """
    )
    conn.close()
    runtime = BlueberryRuntime(load_policy(POLICY), state_path=db, master_key=b"M" * 32)
    lease = runtime.create_lease(agent_id="a", purpose="CLAIM_REVIEW", scope="S")
    assert runtime.protect_value("Max", DataClass.PERSON, lease).startswith("BBM1H.PERSON.")
    runtime.destroy_lease(lease)
    assert runtime.status()["active_agent_handles"] == 0


def test_purge_expired(tmp_path):
    for backend in _backends(tmp_path):
        backend.put("handle", "old", b"x", expires_at=time.time() - 1)
        backend.put("handle", "new", b"x", expires_at=time.time() + 100)
        backend.purge_expired()
        assert backend.list_ids("handle") == ["new"]
