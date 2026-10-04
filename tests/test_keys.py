import base64
import os
import stat
from pathlib import Path

import pytest

from blueberryme.keys import MasterKeyError, load_or_create_master_key, write_master_key_file
from blueberryme.policy import load_policy
from blueberryme.runtime import BlueberryRuntime

POLICY = Path(__file__).parents[1] / "policies" / "eu-business.yaml"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("BBM_MASTER_KEY_B64", "BBM_MASTER_KEY_FILE", "BBM_DEV_MODE"):
        monkeypatch.delenv(name, raising=False)


def test_refuses_to_start_without_key_material(tmp_path):
    with pytest.raises(MasterKeyError):
        load_or_create_master_key(tmp_path / "state")
    assert not (tmp_path / "state" / "master.key").exists()


def test_persistent_runtime_refuses_without_key(tmp_path):
    with pytest.raises(MasterKeyError):
        BlueberryRuntime(load_policy(POLICY), state_path=tmp_path / "state" / "state.db")


def test_env_key_is_used(tmp_path, monkeypatch):
    raw = os.urandom(32)
    monkeypatch.setenv("BBM_MASTER_KEY_B64", base64.urlsafe_b64encode(raw).decode())
    assert load_or_create_master_key(tmp_path) == raw


def test_env_key_wrong_length_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("BBM_MASTER_KEY_B64", base64.b64encode(b"short").decode())
    with pytest.raises(MasterKeyError):
        load_or_create_master_key(tmp_path)


def test_key_file_outside_state_dir_is_used(tmp_path, monkeypatch):
    key_path = write_master_key_file(tmp_path / "secrets" / "bbm.key")
    monkeypatch.setenv("BBM_MASTER_KEY_FILE", str(key_path))
    assert load_or_create_master_key(tmp_path / "state") == key_path.read_bytes()


def test_key_file_inside_state_dir_is_refused(tmp_path, monkeypatch):
    state = tmp_path / "state"
    key_path = write_master_key_file(state / "master.key")
    monkeypatch.setenv("BBM_MASTER_KEY_FILE", str(key_path))
    with pytest.raises(MasterKeyError):
        load_or_create_master_key(state)


def test_missing_key_file_is_not_auto_created(tmp_path, monkeypatch):
    missing = tmp_path / "secrets" / "bbm.key"
    monkeypatch.setenv("BBM_MASTER_KEY_FILE", str(missing))
    with pytest.raises(MasterKeyError):
        load_or_create_master_key(tmp_path / "state")
    assert not missing.exists()


def test_dev_mode_creates_local_key_once(tmp_path, monkeypatch):
    monkeypatch.setenv("BBM_DEV_MODE", "1")
    state = tmp_path / "state"
    first = load_or_create_master_key(state)
    second = load_or_create_master_key(state)
    assert first == second
    assert len(first) == 32
    if os.name == "posix":
        assert stat.S_IMODE((state / "master.key").stat().st_mode) == 0o600


def test_write_master_key_file_refuses_overwrite(tmp_path):
    path = write_master_key_file(tmp_path / "k.key")
    with pytest.raises(FileExistsError):
        write_master_key_file(path)


def test_in_memory_runtime_needs_no_key_material():
    runtime = BlueberryRuntime(load_policy(POLICY))
    assert runtime.status()["active_leases"] == 0
