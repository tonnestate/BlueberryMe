"""Regression tests for races and authority escalation found in the v0.3.0 review."""
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from blueberryme.errors import ErrorCode, JobError
from blueberryme.jobs import AsyncJobGateway
from blueberryme.models import DataClass, SourceReference
from blueberryme.policy import load_policy
from blueberryme.proxy import StructuredToolGuard, TargetAdapter
from blueberryme.references import CallbackSourceAdapter, MemorySourceAdapter
from blueberryme.runtime import BlueberryRuntime

POLICY = Path(__file__).parents[1] / "policies" / "eu-business.yaml"


def _guarded_case_call(runtime, lease):
    case = runtime.protect_value("UV-4711", DataClass.CASE_ID, lease)
    return StructuredToolGuard(runtime).authorize_tool_call(
        {"case": case},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )


def test_concurrent_replay_of_one_intent_reaches_target_once(runtime, lease):
    """v0.3.0 checked 'consumed?' and marked consumed only after the target ran.

    Two concurrent requests with the same intent could both pass. The intent is now
    burned atomically before anything is resolved.
    """
    call = _guarded_case_call(runtime, lease)
    adapter = TargetAdapter(runtime, target_id="SOURCE_SYSTEM")
    hits = []
    gate = threading.Barrier(8)
    results = []

    def handler(args):
        hits.append(args["case"])
        time.sleep(0.05)
        return {"status": "OK"}

    def worker():
        gate.wait()
        results.append(adapter.execute(call, handler, response_schema={"status": DataClass.PUBLIC}))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(hits) == 1
    assert sum(1 for r in results if r["ok"]) == 1
    assert all(r["error"]["code"] == "BBM_INTENT_REPLAY" for r in results if not r["ok"])


def test_replay_is_blocked_across_processes_sharing_sqlite(tmp_path):
    policy = load_policy(POLICY)
    db = tmp_path / "shared.db"
    key = b"S" * 32
    gateway = BlueberryRuntime(policy, state_path=db, master_key=key)
    worker_a = BlueberryRuntime(policy, state_path=db, master_key=key)
    worker_b = BlueberryRuntime(policy, state_path=db, master_key=key)
    lease = gateway.create_lease(
        agent_id="a", purpose="CLAIM_REVIEW", scope="S", allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]}
    )
    call = _guarded_case_call(gateway, lease)
    ok = TargetAdapter(worker_a, target_id="SOURCE_SYSTEM").execute(
        call, lambda a: {"status": "OK"}, response_schema={"status": DataClass.PUBLIC}
    )
    replay = TargetAdapter(worker_b, target_id="SOURCE_SYSTEM").execute(
        call, lambda a: {"status": "OK"}, response_schema={"status": DataClass.PUBLIC}
    )
    assert ok["ok"] is True
    assert replay == {"ok": False, "error": {"code": "BBM_INTENT_REPLAY", "retryable": False}}


def test_tampered_field_map_invalidates_intent(runtime, lease):
    """The field -> class map is signed into the intent, not only the payload."""
    call = _guarded_case_call(runtime, lease)
    tampered = replace(call, reference_fields={})
    response = TargetAdapter(runtime, target_id="SOURCE_SYSTEM").execute(
        tampered, lambda a: {"status": "OK"}, response_schema={"status": DataClass.PUBLIC}
    )
    assert response == {"ok": False, "error": {"code": "BBM_INTENT_INVALID", "retryable": False}}


def test_intent_from_other_lease_is_rejected(runtime, lease):
    call = _guarded_case_call(runtime, lease)
    other = runtime.create_lease(
        agent_id="b", purpose="CLAIM_REVIEW", scope="S", allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]}
    )
    response = TargetAdapter(runtime, target_id="SOURCE_SYSTEM").execute(
        replace(call, lease_id=other), lambda a: {"status": "OK"}, response_schema={"status": DataClass.PUBLIC}
    )
    assert response == {"ok": False, "error": {"code": "BBM_INTENT_INVALID", "retryable": False}}


def _job(runtime, lease):
    runtime.register_source("claims", MemorySourceAdapter({"1": {"case": "UV-1"}}, versions={"1": "1"}))
    view = runtime.protect_reference_record(
        {"case": SourceReference("claims", "1", "case", "1")}, {"case": DataClass.CASE_ID}, lease
    )
    call = StructuredToolGuard(runtime).authorize_tool_call(
        {"case": view["case"]},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    jobs = AsyncJobGateway(runtime)
    return jobs, jobs.submit(call, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)


def test_two_workers_never_run_the_same_job_concurrently(runtime, lease):
    jobs, job = _job(runtime, lease)
    calls = []
    gate = threading.Barrier(6)
    outcomes = []

    def handler(args, idempotency_key=None):
        calls.append(idempotency_key)
        time.sleep(0.1)
        return {"case": args["case"]}

    def worker():
        gate.wait()
        try:
            outcomes.append(jobs.execute(job, handler)["status"])
        except JobError as exc:
            outcomes.append(exc.code.value)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert calls == [job]
    assert outcomes.count("COMPLETED") >= 1
    assert set(outcomes) <= {"COMPLETED", "BBM_JOB_ALREADY_RUNNING"}


def test_job_of_crashed_worker_is_recovered_after_claim_expiry(runtime, lease):
    jobs, job = _job(runtime, lease)
    backend = runtime.secure_state.backend
    # Simulate a worker that claimed the job, marked it RUNNING and died.
    assert backend.try_claim(f"job:{job}", "dead-worker", 0.05)
    state = runtime.secure_state.get_json("job", job)
    state["status"] = "RUNNING"
    runtime.secure_state.put_json("job", job, state)
    with pytest.raises(JobError) as exc:
        jobs.execute(job, lambda args: {"case": args["case"]})
    assert exc.value.code is ErrorCode.JOB_ALREADY_RUNNING
    time.sleep(0.1)
    assert jobs.execute(job, lambda args: {"case": args["case"]})["status"] == "COMPLETED"


def test_cancel_while_running_discards_result(runtime, lease):
    jobs, job = _job(runtime, lease)

    def handler(args):
        jobs.cancel(job)  # cancel arrives while the target runs
        return {"case": args["case"]}

    assert jobs.execute(job, handler)["status"] == "CANCELLED"
    stored = runtime.secure_state.get_json("job", job)
    assert stored["result"] is None and stored["envelope"] is None


def test_concurrent_result_retrieval_succeeds_once(runtime, lease):
    jobs, job = _job(runtime, lease)
    jobs.execute(job, lambda args: {"case": args["case"]})
    gate = threading.Barrier(5)
    outcomes = []

    def fetch():
        gate.wait()
        try:
            jobs.get_result(job, tenant_id="tenant-a", agent_id="agent-test", purpose="CLAIM_REVIEW", scope="R")
            outcomes.append("OK")
        except JobError as exc:
            outcomes.append(exc.code.value)

    threads = [threading.Thread(target=fetch) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("OK") == 1


def test_source_read_errors_do_not_leak_through_target_adapter(runtime, lease):
    def broken(reference):
        raise RuntimeError("connection to db://user:pa55word@host failed for Max Mustermann")

    runtime.register_source("crm", CallbackSourceAdapter(broken))
    view = runtime.protect_reference_record(
        {"case": SourceReference("crm", "1", "case")}, {"case": DataClass.CASE_ID}, lease
    )
    call = StructuredToolGuard(runtime).authorize_tool_call(
        {"case": view["case"]},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    response = TargetAdapter(runtime, target_id="SOURCE_SYSTEM").execute(
        call, lambda a: {"status": "OK"}, response_schema={"status": DataClass.PUBLIC}
    )
    assert response == {"ok": False, "error": {"code": "BBM_SOURCE_UNAVAILABLE", "retryable": True}}
    assert "pa55word" not in str(response)
