from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from blueberryme.api import create_app, create_app_from_env  # noqa: E402
from blueberryme.auth import ApiKeyRegistry, Principal, generate_api_key, hash_api_key  # noqa: E402
from blueberryme.jobs import AsyncJobGateway  # noqa: E402
from blueberryme.policy import load_policy  # noqa: E402
from blueberryme.runtime import BlueberryRuntime  # noqa: E402

POLICY = Path(__file__).parents[1] / "policies" / "eu-business.yaml"
KEY_A = "bbm_test_key_tenant_a_agent_1_0000000000000"
KEY_B = "bbm_test_key_tenant_b_service_000000000000000"
KEY_A_OTHER_AGENT = "bbm_test_key_tenant_a_agent_2_0000000000000"


@pytest.fixture()
def runtime():
    return BlueberryRuntime(load_policy(POLICY), master_key=b"A" * 32)


@pytest.fixture()
def client(runtime):
    registry = ApiKeyRegistry(
        {
            hash_api_key(KEY_A): Principal("tenant-a", frozenset({"CLAIM_REVIEW"}), agent_id="agent-1"),
            hash_api_key(KEY_A_OTHER_AGENT): Principal("tenant-a", frozenset({"CLAIM_REVIEW"}), agent_id="agent-2"),
            hash_api_key(KEY_B): Principal("tenant-b", frozenset({"CLAIM_REVIEW"})),
        }
    )
    return TestClient(create_app(runtime, api_keys=registry))


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _lease(client, key, **extra):
    body = {
        "purpose": "CLAIM_REVIEW",
        "scope": "CASE:1",
        "allowed_operations": {"SOURCE_SYSTEM": ["LOOKUP"]},
        **extra,
    }
    return client.post("/v1/leases", json=body, headers=_h(key))


def _submit_job(client, key):
    lease_id = _lease(client, key).json()["lease_id"]
    protected = client.post(
        "/v1/protect/record",
        json={"lease_id": lease_id, "record": {"case": "UV-1"}, "schema_map": {"case": "CASE_ID"}},
        headers=_h(key),
    )
    assert protected.status_code == 200
    handle = protected.json()["record"]["case"]
    submitted = client.post(
        "/v1/jobs",
        json={
            "lease_id": lease_id,
            "target": "SOURCE_SYSTEM",
            "operation": "LOOKUP",
            "payload": {"case": handle},
            "reference_fields": {"case": "CASE_ID"},
            "response_schema": {"case": "CASE_ID"},
        },
        headers=_h(key),
    )
    assert submitted.status_code == 200
    return submitted.json()["job_handle"]


def test_requests_without_valid_key_are_rejected(client):
    assert client.get("/v1/status").status_code == 401
    assert client.get("/v1/status", headers=_h("bbm_wrong")).status_code == 401
    r = client.post("/v1/leases", json={"agent_id": "x", "purpose": "CLAIM_REVIEW", "scope": "s"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "BBM_UNAUTHENTICATED"
    assert client.get("/v1/status", headers=_h(KEY_A)).status_code == 200


def test_tenant_and_agent_come_from_key(client, runtime):
    r = _lease(client, KEY_A)
    assert r.status_code == 200
    assert runtime.lease_identity(r.json()["lease_id"]) == {
        "tenant_id": "tenant-a",
        "agent_id": "agent-1",
        "purpose": "CLAIM_REVIEW",
    }


def test_spoofed_tenant_or_agent_is_denied(client):
    assert _lease(client, KEY_A, tenant_id="tenant-b").status_code == 403
    assert _lease(client, KEY_A, agent_id="agent-2").status_code == 403


def test_service_key_must_name_agent(client):
    assert _lease(client, KEY_B).status_code == 400
    assert _lease(client, KEY_B, agent_id="svc-agent").status_code == 200


def test_purpose_outside_key_is_denied(client):
    r = client.post(
        "/v1/leases",
        json={"purpose": "MARKETING", "scope": "s"},
        headers=_h(KEY_A),
    )
    assert r.status_code == 403


def test_foreign_tenant_cannot_use_lease(client):
    lease_id = _lease(client, KEY_A).json()["lease_id"]
    r = client.post(
        "/v1/protect/record",
        json={"lease_id": lease_id, "record": {"case": "UV-1"}, "schema_map": {"case": "CASE_ID"}},
        headers=_h(KEY_B),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "BBM_LEASE_UNKNOWN"
    assert client.delete(f"/v1/leases/{lease_id}", headers=_h(KEY_B)).status_code == 403
    assert client.delete(f"/v1/leases/{lease_id}", headers=_h(KEY_A)).json() == {"destroyed": True}


def test_other_agent_of_same_tenant_cannot_use_lease(client):
    lease_id = _lease(client, KEY_A).json()["lease_id"]
    r = client.post(
        "/v1/protect/text",
        json={"lease_id": lease_id, "text": "hello"},
        headers=_h(KEY_A_OTHER_AGENT),
    )
    assert r.status_code == 403


def test_foreign_tenant_cannot_read_or_cancel_job(client):
    job = _submit_job(client, KEY_A)
    r = client.get(f"/v1/jobs/{job}", headers=_h(KEY_B))
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "BBM_JOB_UNKNOWN"
    assert client.delete(f"/v1/jobs/{job}", headers=_h(KEY_B)).status_code == 403
    assert client.get(f"/v1/jobs/{job}", headers=_h(KEY_A)).json()["status"] == "QUEUED"


def test_only_submitting_agent_retrieves_result_once(client, runtime):
    job = _submit_job(client, KEY_A)
    AsyncJobGateway(runtime).execute(job, lambda args: {"case": args["case"]})
    body = {"purpose": "CLAIM_REVIEW", "scope": "CASE:1:RESULT"}

    foreign = {**body, "agent_id": "svc-agent"}  # service keys must name the agent
    r = client.post(f"/v1/jobs/{job}/result", json=foreign, headers=_h(KEY_B))
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "BBM_JOB_UNKNOWN"
    assert client.post(f"/v1/jobs/{job}/result", json=body, headers=_h(KEY_A_OTHER_AGENT)).status_code == 403

    ok = client.post(f"/v1/jobs/{job}/result", json=body, headers=_h(KEY_A))
    assert ok.status_code == 200
    assert ok.json()["result"]["case"].startswith("BBM1H.CASE_ID.")
    assert "UV-1" not in ok.text

    again = client.post(f"/v1/jobs/{job}/result", json=body, headers=_h(KEY_A))
    assert again.status_code == 403
    assert again.json()["detail"]["code"] == "BBM_JOB_RESULT_EXPIRED"


def test_create_app_requires_keys_unless_explicitly_unauthenticated(runtime):
    with pytest.raises(ValueError):
        create_app(runtime, api_keys=None)


def test_create_app_from_env_requires_key_file(monkeypatch):
    monkeypatch.delenv("BBM_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("BBM_DEV_MODE", raising=False)
    with pytest.raises(RuntimeError):
        create_app_from_env()


def test_unauthenticated_dev_mode_keeps_body_identity(runtime):
    client = TestClient(create_app(runtime, api_keys=None, allow_unauthenticated=True))
    r = client.post(
        "/v1/leases",
        json={"agent_id": "dev-agent", "purpose": "CLAIM_REVIEW", "scope": "s", "tenant_id": "dev"},
    )
    assert r.status_code == 200
    assert runtime.lease_identity(r.json()["lease_id"])["tenant_id"] == "dev"


def test_key_file_round_trip(tmp_path):
    key, digest = generate_api_key()
    path = tmp_path / "keys.yaml"
    path.write_text(
        f"keys:\n  - sha256: {digest}\n    tenant_id: tenant-a\n    purposes: [CLAIM_REVIEW]\n    agent_id: agent-1\n",
        encoding="utf-8",
    )
    registry = ApiKeyRegistry.from_file(path)
    principal = registry.authenticate(key)
    assert principal == Principal("tenant-a", frozenset({"CLAIM_REVIEW"}), "agent-1")
    assert registry.authenticate(key + "x") is None
    assert key not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "content",
    [
        "keys: []\n",
        "keys:\n  - sha256: nothex\n    tenant_id: t\n    purposes: [P]\n",
        "keys:\n  - sha256: " + "a" * 64 + "\n    purposes: [P]\n",
        "keys:\n  - sha256: " + "a" * 64 + "\n    tenant_id: t\n    purposes: []\n",
        "keys:\n  - sha256: " + "a" * 64 + "\n    tenant_id: t\n    purposes: [P]\n"
        "  - sha256: " + "a" * 64 + "\n    tenant_id: u\n    purposes: [P]\n",
    ],
)
def test_invalid_key_files_are_rejected(tmp_path, content):
    path = tmp_path / "keys.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        ApiKeyRegistry.from_file(path)
