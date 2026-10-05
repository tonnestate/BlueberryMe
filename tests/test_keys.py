import pytest

from blueberryme.keys import load_or_create_master_key


def test_persistent_key_fails_closed_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("BBM_MASTER_KEY_B64", raising=False)
    monkeypatch.delenv("BBM_MASTER_KEY_FILE", raising=False)
    monkeypatch.delenv("BBM_DEV_MODE", raising=False)

    with pytest.raises(RuntimeError):
        load_or_create_master_key(tmp_path)

    assert not (tmp_path / "master.key").exists()


def test_dev_mode_may_create_local_key(monkeypatch, tmp_path):
    monkeypatch.delenv("BBM_MASTER_KEY_B64", raising=False)
    monkeypatch.delenv("BBM_MASTER_KEY_FILE", raising=False)
    monkeypatch.setenv("BBM_DEV_MODE", "1")

    first = load_or_create_master_key(tmp_path)
    second = load_or_create_master_key(tmp_path)

    assert len(first) == 32
    assert second == first
    assert (tmp_path / "master.key").read_bytes() == first
