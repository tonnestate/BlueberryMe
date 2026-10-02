from __future__ import annotations

import base64
import inspect
import secrets
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping, Sequence

from .crypto import JOB_HANDLE_RE, args_hash, random_job_handle
from .errors import BlueberryError, ErrorCode, InfrastructureError, JobError, SafeTargetError, StructureDenied
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
    DEFAULT_RUN_LEASE_SECONDS = 60
    _UPDATE_ATTEMPTS = 8

    def __init__(self, runtime: BlueberryRuntime, *, run_lease_seconds: int = DEFAULT_RUN_LEASE_SECONDS) -> None:
        """`run_lease_seconds` bounds how long a worker claim is honoured.

        A job left in RUNNING by a crashed worker becomes claimable again once its
        claim expires. Choose a value above the longest expected handler runtime:
        a handler that outlives its claim may be executed a second time, and only the
        target's idempotency key (job_id) then prevents a duplicate side effect.
        """
        if run_lease_seconds < 1 or run_lease_seconds > 86_400:
            raise ValueError("run_lease_seconds must be between 1 and 86400")
        self.runtime = runtime
        self.run_lease_seconds = run_lease_seconds

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
            "owner": {
                "tenant_id": str(envelope["tenant_id"]),
                "agent_id": str(envelope["agent_id"]),
                "purpose": str(envelope["purpose"]),
            },
            "attempt": 0,
            "claim_id": None,
            "running_until": None,
        }
        self.runtime.secure_state.put_json(self.KIND, job_id, job)
        return job_id

    def _load_versioned(self, job_handle: str) -> tuple[dict[str, Any], bytes]:
        if not JOB_HANDLE_RE.fullmatch(job_handle):
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        item, token = self.runtime.secure_state.get_json_with_token(self.KIND, job_handle)
        if item is None or token is None:
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        return item, token

    def _load(self, job_handle: str) -> dict[str, Any]:
        return self._load_versioned(job_handle)[0]

    def _try_save(self, job: dict[str, Any], token: bytes) -> bytes | None:
        """Conditional write. Returns the new token, or None if the job changed meanwhile."""
        job["updated_at"] = datetime.now(UTC).isoformat()
        return self.runtime.secure_state.put_json_if(self.KIND, str(job["job_id"]), job, token)

    def _update(
        self,
        job_handle: str,
        mutate: Callable[[dict[str, Any]], tuple[bool, Any]],
    ) -> Any:
        """Read-modify-write with optimistic concurrency.

        `mutate` returns (write, outcome). If `outcome` is an exception it is raised
        after the write succeeded; otherwise it is returned.
        """
        for _ in range(self._UPDATE_ATTEMPTS):
            job, token = self._load_versioned(job_handle)
            write, outcome = mutate(job)
            if write and self._try_save(job, token) is None:
                continue
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        raise InfrastructureError("Job state contention")

    @staticmethod
    def _owner(job: dict[str, Any]) -> dict[str, str] | None:
        owner = job.get("owner")
        if owner:
            return owner
        envelope = job.get("envelope")
        if envelope:
            # Jobs created before owner binding was stored separately.
            env = _unpack(envelope)
            return {
                "tenant_id": str(env["tenant_id"]),
                "agent_id": str(env["agent_id"]),
                "purpose": str(env["purpose"]),
            }
        return None

    def _check_owner(self, job: dict[str, Any], tenant_id: str | None, agent_id: str | None) -> dict[str, str] | None:
        """Callers that pass an identity only see their own jobs.

        A mismatch is reported as JOB_UNKNOWN so job existence is not disclosed.
        """
        owner = self._owner(job)
        if tenant_id is None and agent_id is None:
            return owner
        if owner is None:
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        if tenant_id is not None and owner["tenant_id"] != tenant_id:
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        if agent_id is not None and owner["agent_id"] != agent_id:
            raise JobError(code=ErrorCode.JOB_UNKNOWN)
        return owner

    @staticmethod
    def _status_view(job: dict[str, Any]) -> dict[str, Any]:
        out = {"job_handle": job["job_id"], "status": job["status"]}
        if job.get("error_code"):
            out["error"] = {"code": job["error_code"]}
        return out

    @staticmethod
    def _expire(job: dict[str, Any], code: ErrorCode = ErrorCode.JOB_EXPIRED) -> None:
        job["status"] = JobStatus.EXPIRED.value
        job["error_code"] = code.value
        job["envelope"] = None
        job["result"] = None
        job["running_until"] = None

    def status(self, job_handle: str, *, tenant_id: str | None = None, agent_id: str | None = None) -> dict[str, Any]:
        def mutate(job: dict[str, Any]) -> tuple[bool, Any]:
            self._check_owner(job, tenant_id, agent_id)
            if job["status"] not in {JobStatus.COMPLETED.value, JobStatus.RETRIEVED.value, JobStatus.CANCELLED.value}:
                if job["status"] != JobStatus.EXPIRED.value and datetime.now(UTC) >= datetime.fromisoformat(
                    job["deadline_at"]
                ):
                    self._expire(job)
                    return True, self._status_view(job)
            return False, self._status_view(job)

        return self._update(job_handle, mutate)

    def cancel(self, job_handle: str, *, tenant_id: str | None = None, agent_id: str | None = None) -> dict[str, Any]:
        def mutate(job: dict[str, Any]) -> tuple[bool, Any]:
            self._check_owner(job, tenant_id, agent_id)
            if job["status"] in {JobStatus.COMPLETED.value, JobStatus.RETRIEVED.value, JobStatus.CANCELLED.value}:
                return False, self._status_view(job)
            job["status"] = JobStatus.CANCELLED.value
            job["error_code"] = ErrorCode.JOB_CANCELLED.value
            job["envelope"] = None
            job["result"] = None
            job["running_until"] = None
            # Idempotent; also guarantees a worker that is mid-flight cannot re-validate.
            self.runtime.intent_authority.consume(str(job["intent"]["intent_id"]))
            return True, self._status_view(job)

        return self._update(job_handle, mutate)

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

    def _claim(self, job_handle: str) -> tuple[dict[str, Any], bytes, dict[str, Any] | None]:
        """Atomically move a job to RUNNING.

        Returns (job, claim_token, None) on a successful claim, or
        (job, token, status_view) when there is nothing to execute.
        """
        job, token = self._load_versioned(job_handle)
        status = JobStatus(job["status"])
        now = datetime.now(UTC)
        if status in {JobStatus.COMPLETED, JobStatus.RETRIEVED, JobStatus.FAILED}:
            return job, token, self._status_view(job)
        if status is JobStatus.CANCELLED:
            raise JobError(code=ErrorCode.JOB_CANCELLED)
        if status is JobStatus.EXPIRED or now >= datetime.fromisoformat(job["deadline_at"]):
            if status is not JobStatus.EXPIRED:
                self._expire(job)
                self._try_save(job, token)
            raise JobError(code=ErrorCode.JOB_EXPIRED)
        if status is JobStatus.RUNNING:
            running_until = job.get("running_until")
            if running_until and now < datetime.fromisoformat(running_until):
                raise JobError(code=ErrorCode.JOB_ALREADY_RUNNING)
            # Claim expired (or legacy job without a claim): the previous worker is
            # presumed dead. Fall through and take the job over.

        envelope = _unpack(job["envelope"])
        intent = _intent_from_json(job["intent"])
        self.runtime.intent_authority.validate_job(
            intent,
            envelope_hash=str(job["envelope_hash"]),
            target=str(envelope["target"]),
            operation=str(envelope["operation"]),
        )

        deadline = datetime.fromisoformat(job["deadline_at"])
        job["status"] = JobStatus.RUNNING.value
        job["error_code"] = None
        job["running_until"] = min(now + timedelta(seconds=self.run_lease_seconds), deadline).isoformat()
        job["attempt"] = int(job.get("attempt") or 0) + 1
        job["claim_id"] = secrets.token_urlsafe(12)
        claim_token = self._try_save(job, token)
        if claim_token is None:
            # Another worker claimed, cancelled or expired the job between our read and write.
            raise JobError(code=ErrorCode.JOB_ALREADY_RUNNING)
        return job, claim_token, None

    def _finish(self, job: dict[str, Any], claim_token: bytes, *, consume_intent: bool) -> dict[str, Any]:
        """Persist the outcome only if this worker still owns the claim."""
        job["running_until"] = None
        if self._try_save(job, claim_token) is None:
            # Cancelled, expired or taken over after our claim expired. The other
            # writer's state wins; this worker's outcome is discarded.
            return self._status_view(self._load(str(job["job_id"])))
        if consume_intent:
            self.runtime.intent_authority.consume(str(job["intent"]["intent_id"]))
        return self._status_view(job)

    def execute(self, job_handle: str, handler: Callable[..., Any]) -> dict[str, Any]:
        """Trusted worker execution. This method must not be exposed to the agent zone."""
        job, claim_token, done = self._claim(job_handle)
        if done is not None:
            return done
        envelope = _unpack(job["envelope"])

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
            return self._finish(job, claim_token, consume_intent=True)
        except SafeTargetError as exc:
            terminal = not exc.retryable
            job["status"] = JobStatus.FAILED.value if terminal else JobStatus.QUEUED.value
            job["error_code"] = exc.code
            return self._finish(job, claim_token, consume_intent=terminal)
        except BlueberryError as exc:
            # Infrastructure failures can be retried; policy/rehydration failures are terminal.
            terminal = exc.failure_class.value != "INFRASTRUCTURE"
            job["status"] = JobStatus.FAILED.value if terminal else JobStatus.QUEUED.value
            job["error_code"] = exc.code.value
            return self._finish(job, claim_token, consume_intent=terminal)
        except Exception:
            job["status"] = JobStatus.FAILED.value
            job["error_code"] = ErrorCode.TARGET_ERROR.value
            return self._finish(job, claim_token, consume_intent=True)

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
        submitter_agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve a completed result exactly once, re-tokenised on a new lease.

        `agent_id` names the agent for the new result lease (it may be a new session).
        Pass `submitter_agent_id` to additionally require that the job was submitted
        by that agent.
        """
        job, token = self._load_versioned(job_handle)
        owner = self._check_owner(job, tenant_id, submitter_agent_id)
        if job["status"] == JobStatus.RETRIEVED.value:
            raise JobError(code=ErrorCode.JOB_RESULT_EXPIRED)
        if job["status"] != JobStatus.COMPLETED.value:
            raise JobError(code=ErrorCode.JOB_NOT_READY)
        if owner is None or owner["purpose"] != purpose:
            raise JobError(code=ErrorCode.JOB_PURPOSE_MISMATCH)
        if not self.runtime.purpose_active(tenant_id, purpose):
            raise JobError(code=ErrorCode.PURPOSE_REVOKED)
        result_expires_at = job.get("result_expires_at")
        if not result_expires_at or datetime.now(UTC) >= datetime.fromisoformat(result_expires_at):
            self._expire(job, ErrorCode.JOB_RESULT_EXPIRED)
            self._try_save(job, token)
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
        try:
            protected = self.runtime.protect_record(raw_result, schema, lease_id)
        except Exception:
            self.runtime.destroy_lease(lease_id)
            raise

        # Data minimisation: once retrieved, the trusted job/result payload is discarded.
        job["status"] = JobStatus.RETRIEVED.value
        job["result_retrieved"] = True
        job["result"] = None
        job["envelope"] = None
        if self._try_save(job, token) is None:
            # A concurrent retrieval, cancellation or expiry won. Exactly one caller gets the result.
            self.runtime.destroy_lease(lease_id)
            raise JobError(code=ErrorCode.JOB_RESULT_EXPIRED)
        return {"job_handle": job_handle, "lease_id": lease_id, "result": protected}
