from __future__ import annotations

import base64
import inspect
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping, Sequence

from .crypto import JOB_HANDLE_RE, args_hash, random_job_handle
from .errors import BlueberryError, ErrorCode, JobError, SafeTargetError, StructureDenied
from .models import DataClass, GuardedCall, JobIntent, JobStatus, ReferenceKind
from .references import ExportedReference
from .runtime import BlueberryRuntime


def _pack(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"__bbm_type__": "bytes", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(k): _pack(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_pack(v) for v in value]
    if isinstance(value, tuple):
        return {"__bbm_type__": "tuple", "data": [_pack(v) for v in value]}
    return value


def _unpack(value: Any) -> Any:
    if isinstance(value, dict) and value.get("__bbm_type__") == "bytes":
        return base64.b64decode(value["data"])
    if isinstance(value, dict) and value.get("__bbm_type__") == "tuple":
        return tuple(_unpack(v) for v in value["data"])
    if isinstance(value, dict):
        return {k: _unpack(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unpack(v) for v in value]
    return value


def _intent_to_json(intent: JobIntent) -> dict[str, Any]:
    return intent.__dict__.copy()


def _intent_from_json(item: dict[str, Any]) -> JobIntent:
    return JobIntent(**{k: str(v) for k, v in item.items()})


class AsyncJobGateway:
    """Bounded async jobs without lease renewal or a workflow engine.

    The job stores encrypted source references/capsules inside the trusted state store,
    never an agent lease. The original lease may expire immediately after submission.
    """

    KIND = "job"

    def __init__(self, runtime: BlueberryRuntime) -> None:
        self.runtime = runtime

    def submit(
        self,
        call: GuardedCall,
        *,
        response_schema: Mapping[str, DataClass | str],
        deadline_seconds: int = 3600,
        result_ttl_seconds: int = 3600,
    ) -> str:
        if deadline_seconds < 1 or deadline_seconds > 86_400:
            raise ValueError("deadline_seconds must be between 1 and 86400")
        if result_ttl_seconds < 1 or result_ttl_seconds > 86_400:
            raise ValueError("result_ttl_seconds must be between 1 and 86400")

        # Policy check #1 happens while converting lease handles into references.
        envelope = self.runtime.export_guarded_call_for_job(call)
        job_id = random_job_handle()
        envelope_hash = args_hash(_pack(envelope))
        intent = self.runtime.intent_authority.mint_job(
            job_id=job_id,
            tenant_id=str(envelope["tenant_id"]),
            purpose=str(envelope["purpose"]),
            target=str(envelope["target"]),
            operation=str(envelope["operation"]),
            envelope_hash=envelope_hash,
            policy_version=self.runtime.policy.version,
            deadline_seconds=deadline_seconds,
        )
        now = datetime.now(UTC)
        job = {
            "job_id": job_id,
            "status": JobStatus.QUEUED.value,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "deadline_at": (now + timedelta(seconds=deadline_seconds)).isoformat(),
            "result_ttl_seconds": result_ttl_seconds,
            "result_expires_at": None,
            "result_retrieved": False,
            "error_code": None,
            "envelope": _pack(envelope),
            "envelope_hash": envelope_hash,
            "intent": _intent_to_json(intent),
            "response_schema": {
                field: (dc.value if isinstance(dc, DataClass) else DataClass(dc).value)
                for field, dc in response_schema.items()
            },
            "result": None,
        }
        self.runtime.secure_state.put_json(self.KIND, job_id, job)
        return job_id

    def _load(self, job_handle: str) -> dict[str, Any]:
        if not JOB_HANDLE_RE.fullmatch(job_handle):
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        item = self.runtime.secure_state.get_json(self.KIND, job_handle)
        if item is None:
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        return item

    def _save(self, job: dict[str, Any]) -> None:
        job["updated_at"] = datetime.now(UTC).isoformat()
        self.runtime.secure_state.put_json(self.KIND, str(job["job_id"]), job)

    @staticmethod
    def _status_view(job: dict[str, Any]) -> dict[str, Any]:
        out = {"job_handle": job["job_id"], "status": job["status"]}
        if job.get("error_code"):
            out["error"] = {"code": job["error_code"]}
        return out

    def status(self, job_handle: str) -> dict[str, Any]:
        job = self._load(job_handle)
        if job["status"] not in {JobStatus.COMPLETED.value, JobStatus.RETRIEVED.value, JobStatus.CANCELLED.value}:
            if datetime.now(UTC) >= datetime.fromisoformat(job["deadline_at"]):
                job["status"] = JobStatus.EXPIRED.value
                job["error_code"] = ErrorCode.JOB_EXPIRED.value
                job["envelope"] = None
                job["result"] = None
                self._save(job)
        return self._status_view(job)

    def cancel(self, job_handle: str) -> dict[str, Any]:
        job = self._load(job_handle)
        if job["status"] in {JobStatus.COMPLETED.value, JobStatus.RETRIEVED.value}:
            return self._status_view(job)
        job["status"] = JobStatus.CANCELLED.value
        job["error_code"] = ErrorCode.JOB_CANCELLED.value
        job["envelope"] = None
        job["result"] = None
        intent = _intent_from_json(job["intent"])
        self.runtime.intent_authority.consume(intent.intent_id)
        self._save(job)
        return self._status_view(job)

    @staticmethod
    def _call_handler(handler: Callable[..., Any], payload: dict[str, Any], job_id: str) -> Any:
        try:
            sig = inspect.signature(handler)
            accepts_key = "idempotency_key" in sig.parameters or any(
                p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            )
        except (TypeError, ValueError):
            accepts_key = False
        if accepts_key:
            return handler(payload, idempotency_key=job_id)
        return handler(payload)

    def execute(self, job_handle: str, handler: Callable[..., Any]) -> dict[str, Any]:
        """Trusted worker execution. This method must not be exposed to the agent zone."""
        job = self._load(job_handle)
        status = JobStatus(job["status"])
        if status in {JobStatus.COMPLETED, JobStatus.RETRIEVED}:
            return self._status_view(job)
        if status is JobStatus.CANCELLED:
            raise JobError(code=ErrorCode.JOB_CANCELLED)
        if status is JobStatus.EXPIRED or datetime.now(UTC) >= datetime.fromisoformat(job["deadline_at"]):
            job["status"] = JobStatus.EXPIRED.value
            job["error_code"] = ErrorCode.JOB_EXPIRED.value
            job["envelope"] = None
            self._save(job)
            raise JobError(code=ErrorCode.JOB_EXPIRED)
        if status is JobStatus.RUNNING:
            raise JobError(code=ErrorCode.JOB_ALREADY_RUNNING)

        envelope = _unpack(job["envelope"])
        intent = _intent_from_json(job["intent"])
        self.runtime.intent_authority.validate_job(
            intent,
            envelope_hash=str(job["envelope_hash"]),
            target=str(envelope["target"]),
            operation=str(envelope["operation"]),
        )

        job["status"] = JobStatus.RUNNING.value
        job["error_code"] = None
        self._save(job)

        try:
            # Policy check #2 occurs at execution time, after possible revocation or policy change.
            resolved = deepcopy(envelope["passthrough"])
            for field, item in envelope["references"].items():
                exported = ExportedReference(
                    kind=ReferenceKind(item["kind"]),
                    data_class=DataClass(item["data_class"]),
                    payload=dict(item["payload"]),
                )
                resolved[field] = self.runtime.resolve_exported_for_job(
                    exported,
                    tenant_id=str(envelope["tenant_id"]),
                    purpose=str(envelope["purpose"]),
                    origin_scope=str(item["origin_scope"]),
                    target=str(envelope["target"]),
                    operation=str(envelope["operation"]),
                    capability_target=item.get("target"),
                    capability_operation=item.get("operation"),
                )

            result = self._call_handler(handler, resolved, job_handle)
            if result is None:
                result = {}
            if not isinstance(result, Mapping):
                raise StructureDenied()
            job["result"] = _pack(dict(result))
            job["result_expires_at"] = (
                datetime.now(UTC) + timedelta(seconds=int(job["result_ttl_seconds"]))
            ).isoformat()
            job["status"] = JobStatus.COMPLETED.value
            job["error_code"] = None
            self.runtime.intent_authority.consume(intent.intent_id)
            self._save(job)
            return self._status_view(job)
        except SafeTargetError as exc:
            if exc.retryable:
                job["status"] = JobStatus.QUEUED.value
            else:
                job["status"] = JobStatus.FAILED.value
                self.runtime.intent_authority.consume(intent.intent_id)
            job["error_code"] = exc.code
            self._save(job)
            return self._status_view(job)
        except BlueberryError as exc:
            # Infrastructure failures can be retried; policy/rehydration failures are terminal.
            if exc.failure_class.value == "INFRASTRUCTURE":
                job["status"] = JobStatus.QUEUED.value
            else:
                job["status"] = JobStatus.FAILED.value
                self.runtime.intent_authority.consume(intent.intent_id)
            job["error_code"] = exc.code.value
            self._save(job)
            return self._status_view(job)
        except Exception:
            job["status"] = JobStatus.FAILED.value
            job["error_code"] = ErrorCode.TARGET_ERROR.value
            self.runtime.intent_authority.consume(intent.intent_id)
            self._save(job)
            return self._status_view(job)

    def get_result(
        self,
        job_handle: str,
        *,
        tenant_id: str,
        agent_id: str,
        purpose: str,
        scope: str,
        allowed_operations: Mapping[str, Sequence[str]] | None = None,
        lease_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        job = self._load(job_handle)
        if job["status"] == JobStatus.RETRIEVED.value:
            raise JobError(code=ErrorCode.JOB_RESULT_EXPIRED)
        if job["status"] != JobStatus.COMPLETED.value:
            raise JobError(code=ErrorCode.JOB_NOT_READY)
        envelope = _unpack(job["envelope"])
        if str(envelope["tenant_id"]) != tenant_id or str(envelope["purpose"]) != purpose:
            raise JobError(code=ErrorCode.JOB_PURPOSE_MISMATCH)
        if not self.runtime.purpose_active(tenant_id, purpose):
            raise JobError(code=ErrorCode.PURPOSE_REVOKED)
        result_expires_at = job.get("result_expires_at")
        if not result_expires_at or datetime.now(UTC) >= datetime.fromisoformat(result_expires_at):
            job["status"] = JobStatus.EXPIRED.value
            job["result"] = None
            job["envelope"] = None
            job["error_code"] = ErrorCode.JOB_RESULT_EXPIRED.value
            self._save(job)
            raise JobError(code=ErrorCode.JOB_RESULT_EXPIRED)

        lease_id = self.runtime.create_lease(
            tenant_id=tenant_id,
            agent_id=agent_id,
            purpose=purpose,
            scope=scope,
            ttl_seconds=lease_ttl_seconds,
            allowed_operations=allowed_operations,
        )
        raw_result = _unpack(job["result"])
        schema = {field: DataClass(dc) for field, dc in job["response_schema"].items()}
        protected = self.runtime.protect_record(raw_result, schema, lease_id)

        # Data minimisation: once retrieved, the trusted job/result payload is discarded.
        job["status"] = JobStatus.RETRIEVED.value
        job["result_retrieved"] = True
        job["result"] = None
        job["envelope"] = None
        self._save(job)
        return {"job_handle": job_handle, "lease_id": lease_id, "result": protected}
