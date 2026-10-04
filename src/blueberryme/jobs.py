from __future__ import annotations

import base64
import inspect
import secrets
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping, Sequence

from .crypto import JOB_HANDLE_RE, args_hash, random_job_handle
from .errors import BlueberryError, ErrorCode, JobError, SafeTargetError, StructureDenied
from .models import DataClass, GuardedCall, JobIntent, JobStatus, ReferenceKind
from .references import ExportedReference
from .runtime import SECRET_REMOVED, BlueberryRuntime, EchoValue


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
            "tenant_id": str(envelope["tenant_id"]),
            "agent_id": str(envelope["agent_id"]),
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
            "echo": None,
            "response_schema": {
                field: (dc.value if isinstance(dc, DataClass) else DataClass(dc).value)
                for field, dc in response_schema.items()
            },
            "result": None,
        }
        self.runtime.secure_state.put_json(self.KIND, job_id, job)
        return job_id

    def _load(self, job_handle: str, *, agent_id: str | None = None) -> dict[str, Any]:
        if not isinstance(job_handle, str) or not JOB_HANDLE_RE.fullmatch(job_handle):
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        item = self.runtime.secure_state.get_json(self.KIND, job_handle)
        if item is None:
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        # Another agent's job is indistinguishable from a job that does not exist.
        if agent_id is not None and item.get("agent_id") != agent_id:
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

    def status(self, job_handle: str, *, agent_id: str | None = None) -> dict[str, Any]:
        job = self._load(job_handle, agent_id=agent_id)
        if job["status"] not in {JobStatus.COMPLETED.value, JobStatus.RETRIEVED.value, JobStatus.CANCELLED.value}:
            if datetime.now(UTC) >= datetime.fromisoformat(job["deadline_at"]):
                job["status"] = JobStatus.EXPIRED.value
                job["error_code"] = ErrorCode.JOB_EXPIRED.value
                self._discard(job)
                self._save(job)
        return self._status_view(job)

    def cancel(self, job_handle: str, *, agent_id: str | None = None) -> dict[str, Any]:
        job = self._load(job_handle, agent_id=agent_id)
        if job["status"] in {JobStatus.COMPLETED.value, JobStatus.RETRIEVED.value}:
            return self._status_view(job)
        job["status"] = JobStatus.CANCELLED.value
        job["error_code"] = ErrorCode.JOB_CANCELLED.value
        self._discard(job)
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

    def _discard(self, job: dict[str, Any]) -> None:
        job["envelope"] = None
        job["result"] = None
        job["echo"] = None

    def execute(
        self,
        job_handle: str,
        handler: Callable[..., Any],
        *,
        claim_ttl_seconds: float = 900,
    ) -> dict[str, Any]:
        """Trusted worker execution. This method must not be exposed to the agent zone.

        A worker must first win an atomic claim on the job, so two workers (threads or
        processes sharing the state store) can never run the same job concurrently. If a
        worker dies, its claim expires after ``claim_ttl_seconds`` and the job can be
        picked up again; the target sees the same ``idempotency_key`` both times.
        ``claim_ttl_seconds`` must exceed the handler's worst-case runtime.
        """
        job = self._load(job_handle)
        if JobStatus(job["status"]) in {JobStatus.COMPLETED, JobStatus.RETRIEVED}:
            return self._status_view(job)

        holder = "BBM1-WORKER-" + secrets.token_urlsafe(12)
        claim = f"job:{job_handle}"
        backend = self.runtime.secure_state.backend
        if not backend.try_claim(claim, holder, claim_ttl_seconds):
            raise JobError(code=ErrorCode.JOB_ALREADY_RUNNING)
        try:
            return self._execute_claimed(job_handle, handler)
        finally:
            backend.release_claim(claim, holder)

    def _execute_claimed(self, job_handle: str, handler: Callable[..., Any]) -> dict[str, Any]:
        # Re-read after winning the claim: another worker may have finished meanwhile.
        job = self._load(job_handle)
        status = JobStatus(job["status"])
        if status in {JobStatus.COMPLETED, JobStatus.RETRIEVED, JobStatus.FAILED}:
            return self._status_view(job)
        if status is JobStatus.CANCELLED:
            raise JobError(code=ErrorCode.JOB_CANCELLED)
        if status is JobStatus.EXPIRED or datetime.now(UTC) >= datetime.fromisoformat(job["deadline_at"]):
            job["status"] = JobStatus.EXPIRED.value
            job["error_code"] = ErrorCode.JOB_EXPIRED.value
            self._discard(job)
            self._save(job)
            raise JobError(code=ErrorCode.JOB_EXPIRED)
        # A RUNNING job without a live claim belongs to a crashed worker: retry it.

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

        def finish(mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
            # A cancel that arrived while the handler ran wins: its result is discarded.
            current = self._load(job_handle)
            if current["status"] == JobStatus.CANCELLED.value:
                return self._status_view(current)
            mutate(current)
            self._save(current)
            return self._status_view(current)

        try:
            # Policy check #2 occurs at execution time, after possible revocation or policy change.
            resolved = deepcopy(envelope["passthrough"])
            echoes: list[dict[str, Any]] = []
            for field, item in envelope["references"].items():
                exported = ExportedReference(
                    kind=ReferenceKind(item["kind"]),
                    data_class=DataClass(item["data_class"]),
                    payload=dict(item["payload"]),
                )
                value = self.runtime.resolve_exported_for_job(
                    exported,
                    tenant_id=str(envelope["tenant_id"]),
                    purpose=str(envelope["purpose"]),
                    origin_scope=str(item["origin_scope"]),
                    target=str(envelope["target"]),
                    operation=str(envelope["operation"]),
                    capability_target=item.get("target"),
                    capability_operation=item.get("operation"),
                )
                resolved[field] = value
                echoes.append(
                    {
                        "value": _pack(value),
                        "data_class": exported.data_class.value,
                        "secret": exported.kind is ReferenceKind.CAPABILITY,
                    }
                )

            result = self._call_handler(handler, resolved, job_handle)
            if result is None:
                result = {}
            if not isinstance(result, Mapping):
                raise StructureDenied()

            def complete(current: dict[str, Any]) -> None:
                current["result"] = _pack(dict(result))
                current["echo"] = echoes
                current["result_expires_at"] = (
                    datetime.now(UTC) + timedelta(seconds=int(current["result_ttl_seconds"]))
                ).isoformat()
                current["status"] = JobStatus.COMPLETED.value
                current["error_code"] = None

            view = finish(complete)
            self.runtime.intent_authority.consume(intent.intent_id)
            return view
        except SafeTargetError as exc:
            return self._fail(finish, intent, retry=exc.retryable, code=exc.code)
        except BlueberryError as exc:
            # Infrastructure failures can be retried; policy/rehydration failures are terminal.
            return self._fail(finish, intent, retry=exc.failure_class.value == "INFRASTRUCTURE", code=exc.code.value)
        except Exception:
            self.runtime.intent_authority.consume(intent.intent_id)

            def crashed(current: dict[str, Any]) -> None:
                current["status"] = JobStatus.FAILED.value
                current["error_code"] = ErrorCode.TARGET_ERROR.value

            return finish(crashed)

    def _fail(
        self, finish: Callable[[Callable[[dict[str, Any]], None]], dict[str, Any]], intent: JobIntent, *, retry: bool, code: str
    ) -> dict[str, Any]:
        if not retry:
            self.runtime.intent_authority.consume(intent.intent_id)

        def mutate(current: dict[str, Any]) -> None:
            current["status"] = JobStatus.QUEUED.value if retry else JobStatus.FAILED.value
            current["error_code"] = code

        return finish(mutate)

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
        """Retrieve a completed result once, re-tokenised under a fresh lease.

        The result is bound to the submitting agent, tenant and purpose. The new lease
        can never grant more target operations than the submitting lease had: requested
        operations are intersected with the original ones (omitted -> original set).
        """
        job = self._load(job_handle)
        if job["status"] == JobStatus.RETRIEVED.value:
            raise JobError(code=ErrorCode.JOB_RESULT_EXPIRED)
        if job["status"] != JobStatus.COMPLETED.value:
            raise JobError(code=ErrorCode.JOB_NOT_READY)
        envelope = _unpack(job["envelope"])
        if (
            str(envelope["tenant_id"]) != tenant_id
            or str(envelope["purpose"]) != purpose
            or str(envelope["agent_id"]) != agent_id
        ):
            raise JobError(code=ErrorCode.JOB_PURPOSE_MISMATCH)
        if not self.runtime.purpose_active(tenant_id, purpose):
            raise JobError(code=ErrorCode.PURPOSE_REVOKED)
        result_expires_at = job.get("result_expires_at")
        if not result_expires_at or datetime.now(UTC) >= datetime.fromisoformat(result_expires_at):
            job["status"] = JobStatus.EXPIRED.value
            job["error_code"] = ErrorCode.JOB_RESULT_EXPIRED.value
            self._discard(job)
            self._save(job)
            raise JobError(code=ErrorCode.JOB_RESULT_EXPIRED)
        # Single retrieval, atomic across concurrent callers and processes.
        if not self.runtime.intent_authority.consume_once(f"result:{job_handle}"):
            raise JobError(code=ErrorCode.JOB_RESULT_EXPIRED)

        original_ops = {str(k): set(map(str, v)) for k, v in (envelope.get("allowed_operations") or {}).items()}
        if allowed_operations is None:
            granted = {k: sorted(v) for k, v in original_ops.items()}
        else:
            granted = {}
            for target, ops in allowed_operations.items():
                base = original_ops.get(str(target), set())
                keep = {str(op) for op in ops if str(op) in base or "*" in base}
                if keep:
                    granted[str(target)] = sorted(keep)

        lease_id = self.runtime.create_lease(
            tenant_id=tenant_id,
            agent_id=agent_id,
            purpose=purpose,
            scope=scope,
            ttl_seconds=lease_ttl_seconds,
            allowed_operations=granted,
        )
        raw_result = _unpack(job["result"])
        schema = {field: DataClass(dc) for field, dc in job["response_schema"].items()}
        echoes = [
            EchoValue(
                value=_unpack(item["value"]),
                data_class=DataClass(item["data_class"]),
                replacement=SECRET_REMOVED if item.get("secret") else "",
            )
            for item in (job.get("echo") or [])
        ]

        def replacement(echo: EchoValue) -> str:
            # Secrets are removed, everything else gets a handle in the *new* lease.
            if echo.replacement == SECRET_REMOVED or echo.data_class is DataClass.SECRET:
                return SECRET_REMOVED
            handle = self.runtime.protect_value(echo.value, echo.data_class, lease_id)
            return handle if isinstance(handle, str) else f"[BBM:{echo.data_class.value}:REMOVED]"

        protected = self.runtime.protect_record(raw_result, schema, lease_id)
        protected = self.runtime.scrub_echoes(protected, echoes, replacement)

        # Data minimisation: once retrieved, the trusted job/result payload is discarded.
        job["status"] = JobStatus.RETRIEVED.value
        job["result_retrieved"] = True
        self._discard(job)
        self._save(job)
        return {"job_handle": job_handle, "lease_id": lease_id, "result": protected}
