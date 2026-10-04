import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from blueberryme.api import GatewayAuth, create_app  # noqa: E402

CONTROL = "c" * 40
AGENT_A = "a" * 40
AGENT_B = "b" * 40


@pytest.fixture()
def client(runtime):
    auth = GatewayAuth(control_token=CONTROL, agent_tokens={AGENT_A: "agent-a", AGENT_B: "agent-b"})
    return TestClient(create_app(runtime, auth))


def h(token):
    return {"Authorization": f"Bearer {token}"}


def _lease(client, agent="agent-a"):
    r = client.post(
        "/v1/leases",
        json={
            "agent_id": agent,
            "purpose": "CLAIM_REVIEW",
            "scope": "CASE:1",
            "allowed_operations": {"MAIL_DELIVERY": ["DELIVER"]},
        },
        headers=h(CONTROL),
    )
    assert r.status_code == 200
    return r.json()["lease_id"]


def test_unconfigured_gateway_fails_closed(runtime):
    c = TestClient(create_app(runtime, GatewayAuth()))
    r = c.post("/v1/leases", json={"agent_id": "a", "purpose": "p", "scope": "s"})
    assert r.status_code == 503
    assert c.get("/v1/jobs/BBM1J.AAAAAAAAAAAAAAAAAAAA").status_code == 503


def test_agent_cannot_mint_its_own_lease(client):
    r = client.post(
        "/v1/leases",
        json={"agent_id": "agent-a", "purpose": "CLAIM_REVIEW", "scope": "s", "allowed_operations": {"*": ["*"]}},
        headers=h(AGENT_A),
    )
    assert r.status_code == 401


def test_missing_or_wrong_token_is_rejected(client):
    assert client.get("/v1/status").status_code == 401
    assert client.get("/v1/status", headers=h("x" * 40)).status_code == 401
    assert client.get("/v1/status", headers=h(CONTROL)).status_code == 200


def test_agent_flow_and_identity_binding(client):
    lease = _lease(client)
    email = client.post(
        "/v1/protect/record",
        json={"lease_id": lease, "record": {"email": "max@example.de"}, "schema_map": {"email": "EMAIL"}},
        headers=h(CONTROL),
    ).json()["record"]["email"]
    body = {
        "lease_id": lease,
        "target": "MAIL_DELIVERY",
        "operation": "DELIVER",
        "payload": {"email": email},
        "reference_fields": {"email": "EMAIL"},
        "response_schema": {"status": "PUBLIC"},
    }
    # Agent B cannot submit with agent A's lease.
    r = client.post("/v1/jobs", json=body, headers=h(AGENT_B))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "BBM_AGENT_MISMATCH"

    job = client.post("/v1/jobs", json=body, headers=h(AGENT_A)).json()["job_handle"]
    assert client.get(f"/v1/jobs/{job}", headers=h(AGENT_A)).json()["status"] == "QUEUED"
    # Agent B cannot even see that the job exists.
    r = client.get(f"/v1/jobs/{job}", headers=h(AGENT_B))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "BBM_JOB_UNKNOWN"
    # Agent B cannot claim agent A's identity in the body.
    r = client.post(
        f"/v1/jobs/{job}/result",
        json={"agent_id": "agent-a", "purpose": "CLAIM_REVIEW", "scope": "R"},
        headers=h(AGENT_B),
    )
    assert r.status_code == 403 and r.json()["detail"]["code"] == "BBM_AGENT_MISMATCH"


def test_no_resolve_endpoint_exists(client):
    paths = {route.path for route in client.app.routes}
    assert not any("resolve" in p or "rehydrate" in p or "decode" in p for p in paths)


def test_weak_or_shared_tokens_are_refused():
    with pytest.raises(ValueError):
        GatewayAuth(control_token="short")
    with pytest.raises(ValueError):
        GatewayAuth(control_token=CONTROL, agent_tokens={CONTROL: "agent-a"})


def test_agent_tokens_parse_from_env(monkeypatch):
    monkeypatch.setenv("BBM_CONTROL_TOKEN", CONTROL)
    monkeypatch.setenv("BBM_AGENT_TOKENS", f"agent-a={AGENT_A}, agent-b={AGENT_B}")
    auth = GatewayAuth.from_env()
    assert auth.agent_tokens == {AGENT_A: "agent-a", AGENT_B: "agent-b"}


def test_source_endpoint_is_public_and_carries_license(client):
    r = client.get("/source")
    assert r.status_code == 200
    assert r.json()["license"] == "AGPL-3.0-only"
