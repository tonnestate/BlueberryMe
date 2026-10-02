import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from blueberryme.errors import ErrorCode, JobError
from blueberryme.jobs import AsyncJobGateway
from blueberryme.models import DataClass, SourceReference
from blueberryme.policy import load_policy
from blueberryme.proxy import StructuredToolGuard
from blueberryme.references import MemorySourceAdapter
from blueberryme.runtime import BlueberryRuntime

POLICY = Path(__file__).parents[1] / "policies" / "eu-business.yaml"


def _register(runtime):
    runtime.register_source("claims", MemorySourceAdapter({"4711": {"case": "UV-4711"}}, versions={"4711": "1"}))


def _submit(runtime, *, agent_id="agent-test", jobs=None):
    _register(runtime)
    lease = runtime.create_lease(
        tenant_id="tenant-a",
        agent_id=agent_id,
        purpose="CLAIM_REVIEW",
        scope="CASE:4711",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )
    view = runtime.protect_reference_record(
        {"case": SourceReference("claims", "4711", "case", "1")},
        {"case": DataClass.CASE_ID},
        lease,
        origin_scope="CASE:4711",
    )
    call = StructuredToolGuard(runtime).authorize_tool_call(
        {"case": view["case"]},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    jobs = jobs or AsyncJobGateway(runtime)
    return jobs, jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=600)


def _force_claim_expired(jobs, handle):
    job = jobs._load(handle)
    job["running_until"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    jobs.runtime.secure_state.put_json(jobs.KIND, handle, job)


def test_live_claim_blocks_second_worker(runtime):
    jobs, handle = _submit(runtime)
    jobs._claim(handle)  # worker A claims and is still running
    with pytest.raises(JobError) as exc:
        jobs.execute(handle, lambda args: {"case": args["case"]})
    assert exc.value.code is ErrorCode.JOB_ALREADY_RUNNING


def test_crashed_worker_claim_is_taken_over_after_expiry(runtime):
    jobs, handle = _submit(runtime)
    jobs._claim(handle)  # worker A claims, then crashes without finishing
    _force_claim_expired(jobs, handle)

    calls = []

    def handler(args, idempotency_key=None):
        calls.append(idempotency_key)
        return {"case": args["case"]}

    status = jobs.execute(handle, handler)
    assert status["status"] == "COMPLETED"
    assert calls == [handle]  # same idempotency key as the crashed attempt would have used
    assert jobs._load(handle)["attempt"] == 2


def test_legacy_running_job_without_claim_is_recoverable(runtime):
    jobs, handle = _submit(runtime)
    job = jobs._load(handle)
    job["status"] = "RUNNING"
    job.pop("running_until", None)
    jobs.runtime.secure_state.put_json(jobs.KIND, handle, job)
    assert jobs.execute(handle, lambda args: {"case": args["case"]})["status"] == "COMPLETED"


def test_stale_writer_loses_compare_and_swap(runtime):
    jobs, handle = _submit(runtime)
    job, stale_token = jobs._load_versioned(handle)
    jobs._claim(handle)  # another worker wins first
    job["status"] = "RUNNING"
    assert jobs._try_save(job, stale_token) is None


def test_cancel_during_execution_discards_result(runtime):
    jobs, handle = _submit(runtime)

    def handler(args):
        jobs.cancel(handle)  # operator cancels while the target call is in flight
        return {"case": args["case"]}

    status = jobs.execute(handle, handler)
    assert status["status"] == "CANCELLED"
    stored = jobs._load(handle)
    assert stored["result"] is None
    assert stored["envelope"] is None


def test_worker_outliving_its_claim_does_not_overwrite_takeover(runtime):
    jobs, handle = _submit(runtime)
    outcomes = []

    def slow_handler(args, idempotency_key=None):
        # While worker A is still inside the target, its claim expires and worker B finishes the job.
        _force_claim_expired(jobs, handle)
        outcomes.append(jobs.execute(handle, lambda a, idempotency_key=None: {"case": "FROM_B"}))
        return {"case": "FROM_A"}

    status_a = jobs.execute(handle, slow_handler)
    assert outcomes[0]["status"] == "COMPLETED"
    assert status_a["status"] == "COMPLETED"
    result = jobs.get_result(
        handle,
        tenant_id="tenant-a",
        agent_id="agent-test",
        purpose="CLAIM_REVIEW",
        scope="CASE:4711:RESULT",
    )
    # B's result was persisted; A's late write was rejected.
    assert result["result"]["case"].startswith("BBM1H.CASE_ID.")
    assert jobs._load(handle)["attempt"] == 2


def test_concurrent_workers_execute_job_once(tmp_path):
    db = tmp_path / "bbm.db"
    key = b"C" * 32
    policy = load_policy(POLICY)
    r_submit = BlueberryRuntime(policy, state_path=db, master_key=key)
    _, handle = _submit(r_submit)

    workers = []
    for _ in range(4):
        r = BlueberryRuntime(policy, state_path=db, master_key=key)
        _register(r)
        workers.append(AsyncJobGateway(r))

    barrier = threading.Barrier(len(workers))
    calls = []
    lock = threading.Lock()
    errors = []

    def handler(args, idempotency_key=None):
        with lock:
            calls.append(idempotency_key)
        return {"case": args["case"]}

    def run(gateway):
        barrier.wait()
        try:
            gateway.execute(handle, handler)
        except JobError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=run, args=(w,)) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 1
    assert all(code is ErrorCode.JOB_ALREADY_RUNNING for code in errors)
    assert workers[0]._load(handle)["status"] == "COMPLETED"


def test_result_is_delivered_exactly_once_under_concurrent_retrieval(runtime):
    jobs, handle = _submit(runtime)
    jobs.execute(handle, lambda args: {"case": args["case"]})

    original = runtime.protect_record
    inner = []

    def racing_protect(record, schema, lease_id):
        runtime.protect_record = original
        # A second caller retrieves the result while the first is still re-tokenising.
        inner.append(
            jobs.get_result(
                handle,
                tenant_id="tenant-a",
                agent_id="agent-test",
                purpose="CLAIM_REVIEW",
                scope="CASE:4711:RESULT",
            )
        )
        return original(record, schema, lease_id)

    runtime.protect_record = racing_protect
    with pytest.raises(JobError) as exc:
        jobs.get_result(
            handle,
            tenant_id="tenant-a",
            agent_id="agent-test",
            purpose="CLAIM_REVIEW",
            scope="CASE:4711:RESULT",
        )
    assert exc.value.code is ErrorCode.JOB_RESULT_EXPIRED
    assert len(inner) == 1
    assert inner[0]["result"]["case"].startswith("BBM1H.CASE_ID.")


def test_other_tenant_cannot_see_or_cancel_job(runtime):
    jobs, handle = _submit(runtime)
    with pytest.raises(JobError) as exc:
        jobs.status(handle, tenant_id="tenant-b")
    assert exc.value.code is ErrorCode.JOB_UNKNOWN
    with pytest.raises(JobError) as exc:
        jobs.cancel(handle, tenant_id="tenant-a", agent_id="agent-other")
    assert exc.value.code is ErrorCode.JOB_UNKNOWN
    assert jobs.status(handle)["status"] == "QUEUED"


def test_submitter_binding_on_result(runtime):
    jobs, handle = _submit(runtime, agent_id="agent-submitter")
    jobs.execute(handle, lambda args: {"case": args["case"]})
    with pytest.raises(JobError) as exc:
        jobs.get_result(
            handle,
            tenant_id="tenant-a",
            agent_id="agent-intruder",
            purpose="CLAIM_REVIEW",
            scope="CASE:4711:RESULT",
            submitter_agent_id="agent-intruder",
        )
    assert exc.value.code is ErrorCode.JOB_UNKNOWN
    ok = jobs.get_result(
        handle,
        tenant_id="tenant-a",
        agent_id="agent-submitter-session-2",
        purpose="CLAIM_REVIEW",
        scope="CASE:4711:RESULT",
        submitter_agent_id="agent-submitter",
    )
    assert ok["result"]["case"].startswith("BBM1H.CASE_ID.")


def test_failed_job_is_not_re_executed(runtime):
    from blueberryme.errors import SafeTargetError

    jobs, handle = _submit(runtime)

    def failing(args):
        raise SafeTargetError("TARGET_REJECTED")

    assert jobs.execute(handle, failing)["status"] == "FAILED"
    calls = []
    assert jobs.execute(handle, lambda args: calls.append(1) or {})["status"] == "FAILED"
    assert calls == []
