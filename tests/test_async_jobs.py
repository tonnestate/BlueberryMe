import pytest

from blueberryme.errors import ErrorCode, JobError
from blueberryme.jobs import AsyncJobGateway
from blueberryme.models import DataClass, SourceReference
from blueberryme.proxy import StructuredToolGuard
from blueberryme.references import MemorySourceAdapter


def _source_call(runtime, lease, value="UV-4711"):
    source = MemorySourceAdapter({"4711": {"case": value}}, versions={"4711": "1"})
    runtime.register_source("claims", source)
    view = runtime.protect_reference_record(
        {"case": SourceReference("claims", "4711", "case", "1")},
        {"case": DataClass.CASE_ID},
        lease,
        origin_scope="CASE:4711",
    )
    guard = StructuredToolGuard(runtime)
    call = guard.authorize_tool_call(
        {"case": view["case"]},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    return source, call


def test_job_carries_pointer_not_original_lease(runtime, lease):
    _, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    runtime.destroy_lease(lease)
    seen = {}
    status = jobs.execute(job, lambda args: seen.update(args) or {"case": args["case"]})
    assert status["status"] == "COMPLETED"
    assert seen["case"] == "UV-4711"


def test_revocation_between_submit_and_execute_denies_job(runtime, lease):
    _, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    runtime.revoke_purpose("tenant-a", "CLAIM_REVIEW")
    status = jobs.execute(job, lambda args: {"case": args["case"]})
    assert status["status"] == "FAILED"
    assert status["error"]["code"] == "BBM_PURPOSE_REVOKED"


def test_async_value_drift_is_safe_failure(runtime, lease):
    source, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    source.set_version_for_test("4711", "2")
    status = jobs.execute(job, lambda args: {"case": args["case"]})
    assert status["status"] == "FAILED"
    assert status["error"]["code"] == "BBM_VALUE_DRIFT"


def test_retry_after_completed_does_not_execute_twice(runtime, lease):
    _, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    calls = []

    def handler(args, idempotency_key=None):
        calls.append((args["case"], idempotency_key))
        return {"case": args["case"]}

    jobs.execute(job, handler)
    jobs.execute(job, handler)
    assert len(calls) == 1
    assert calls[0][1] == job


def test_result_is_retokenized_on_new_lease_and_then_removed(runtime, lease):
    _, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    jobs.execute(job, lambda args: {"case": args["case"]})
    result = jobs.get_result(
        job,
        tenant_id="tenant-a",
        agent_id="agent-test",
        purpose="CLAIM_REVIEW",
        scope="CASE:4711:RESULT",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )
    assert result["result"]["case"].startswith("BBM1H.CASE_ID.")
    assert "UV-4711" not in str(result)
    with pytest.raises(JobError) as exc:
        jobs.get_result(
            job,
            tenant_id="tenant-a",
            agent_id="agent-test",
            purpose="CLAIM_REVIEW",
            scope="CASE:4711:RESULT",
        )
    assert exc.value.code is ErrorCode.JOB_RESULT_EXPIRED


def test_result_is_bound_to_submitting_agent(runtime, lease):
    _, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    jobs.execute(job, lambda args: {"case": args["case"]})
    with pytest.raises(JobError) as exc:
        jobs.get_result(job, tenant_id="tenant-a", agent_id="other-agent", purpose="CLAIM_REVIEW", scope="X")
    assert exc.value.code is ErrorCode.JOB_PURPOSE_MISMATCH
    with pytest.raises(JobError) as exc:
        jobs.status(job, agent_id="other-agent")
    assert exc.value.code is ErrorCode.JOB_UNKNOWN
    # The rightful agent can still fetch it: a failed foreign attempt does not burn it.
    assert jobs.get_result(job, tenant_id="tenant-a", agent_id="agent-test", purpose="CLAIM_REVIEW", scope="X")["result"]


def test_result_lease_cannot_escalate_operations(runtime, lease):
    _, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    jobs.execute(job, lambda args: {"case": args["case"]})
    out = jobs.get_result(
        job,
        tenant_id="tenant-a",
        agent_id="agent-test",
        purpose="CLAIM_REVIEW",
        scope="X",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP", "DELETE_EVERYTHING"], "EVIL_SINK": ["EXFILTRATE"]},
    )
    assert runtime.lease_operations(out["lease_id"]) == {"SOURCE_SYSTEM": ["LOOKUP"]}


def test_result_lease_defaults_to_original_operations(runtime, lease):
    _, call = _source_call(runtime, lease)
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    original = runtime.lease_operations(lease)
    jobs.execute(job, lambda args: {"case": args["case"]})
    out = jobs.get_result(job, tenant_id="tenant-a", agent_id="agent-test", purpose="CLAIM_REVIEW", scope="X")
    assert runtime.lease_operations(out["lease_id"]) == original


def test_async_capsule_path_for_value_without_source(runtime, lease):
    guard = StructuredToolGuard(runtime)
    jobs = AsyncJobGateway(runtime)
    email = runtime.protect_value("user@example.org", DataClass.EMAIL, lease)
    call = guard.authorize_tool_call(
        {"email": email},
        lease_id=lease,
        target="MAIL_DELIVERY",
        operation="DELIVER",
        reference_fields={"email": DataClass.EMAIL},
    )
    job = jobs.submit(call, response_schema={"status": DataClass.PUBLIC}, deadline_seconds=60)
    runtime.destroy_lease(lease)
    seen = {}
    status = jobs.execute(job, lambda args: seen.update(args) or {"status": "SENT"})
    assert status["status"] == "COMPLETED"
    assert seen["email"] == "user@example.org"
