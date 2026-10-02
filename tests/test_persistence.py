from pathlib import Path

from blueberryme.models import DataClass
from blueberryme.policy import load_policy
from blueberryme.runtime import BlueberryRuntime


def test_state_and_audit_survive_restart(tmp_path):
    policy = load_policy(Path(__file__).parents[1] / "policies" / "eu-business.yaml")
    db = tmp_path / "bbm.db"
    key = b"P" * 32
    r1 = BlueberryRuntime(policy, state_path=db, master_key=key)
    lease = r1.create_lease(
        tenant_id="tenant-a",
        agent_id="agent-1",
        purpose="CLAIM_REVIEW",
        scope="CASE:1",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )
    handle = r1.protect_value("UV-1", DataClass.CASE_ID, lease)
    audit1 = r1.audit_events()

    r2 = BlueberryRuntime(policy, state_path=db, master_key=key)
    status = r2.status()
    audit2 = r2.audit_events()
    assert status["active_leases"] == 1
    assert status["active_agent_handles"] == 1
    assert audit2 == audit1
    assert handle.startswith("BBM1H.CASE_ID.")


def test_audit_refs_stable_with_persistent_master_key(tmp_path):
    policy = load_policy(Path(__file__).parents[1] / "policies" / "eu-business.yaml")
    db = tmp_path / "bbm.db"
    key = b"Q" * 32
    r1 = BlueberryRuntime(policy, state_path=db, master_key=key)
    lease = r1.create_lease(
        tenant_id="tenant-a",
        agent_id="agent-1",
        purpose="CLAIM_REVIEW",
        scope="CASE:1",
        allowed_operations={},
    )
    first = r1.audit_events()[0]
    r2 = BlueberryRuntime(policy, state_path=db, master_key=key)
    loaded = r2._active_lease(lease)
    r2._audit_event("TEST", loaded, decision="ALLOW")
    second = r2.audit_events()[-1]
    assert first["agent_ref"] == second["agent_ref"]
    assert first["scope_ref"] == second["scope_ref"]


def test_async_job_survives_runtime_restart(tmp_path):
    from blueberryme.jobs import AsyncJobGateway
    from blueberryme.models import SourceReference
    from blueberryme.proxy import StructuredToolGuard
    from blueberryme.references import MemorySourceAdapter

    policy = load_policy(Path(__file__).parents[1] / "policies" / "eu-business.yaml")
    db = tmp_path / "bbm.db"
    key = b"R" * 32

    r1 = BlueberryRuntime(policy, state_path=db, master_key=key)
    r1.register_source("claims", MemorySourceAdapter({"1": {"case": "UV-1"}}, versions={"1": "1"}))
    lease = r1.create_lease(
        tenant_id="tenant-a",
        agent_id="agent-1",
        purpose="CLAIM_REVIEW",
        scope="CASE:1",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )
    view = r1.protect_reference_record(
        {"case": SourceReference("claims", "1", "case", "1")},
        {"case": DataClass.CASE_ID},
        lease,
    )
    call = StructuredToolGuard(r1).authorize_tool_call(
        {"case": view["case"]},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    job = AsyncJobGateway(r1).submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)

    r2 = BlueberryRuntime(policy, state_path=db, master_key=key)
    r2.register_source("claims", MemorySourceAdapter({"1": {"case": "UV-1"}}, versions={"1": "1"}))
    jobs2 = AsyncJobGateway(r2)
    status = jobs2.execute(job, lambda args: {"case": args["case"]})
    assert status["status"] == "COMPLETED"
