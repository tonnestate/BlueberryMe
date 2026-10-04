from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .auth import ApiKeyRegistry, Principal
from .errors import BlueberryError, ErrorCode, LeaseDenied, PolicyDenied
from .jobs import AsyncJobGateway
from .keys import dev_mode_enabled
from .models import DataClass
from .policy import load_policy
from .proxy import StructuredToolGuard
from .runtime import BlueberryRuntime


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LeaseRequest(StrictModel):
    # With authentication, tenant_id comes from the API key and agent_id from the key
    # when the key is bound to an agent. If sent anyway, they must match.
    agent_id: str | None = None
    purpose: str
    scope: str
    tenant_id: str | None = None
    ttl_seconds: int = Field(default=300, ge=1, le=86400)
    allowed_operations: dict[str, list[str]] = {}


class ProtectRecordRequest(StrictModel):
    lease_id: str
    record: dict[str, Any]
    schema_map: dict[str, DataClass]


class ProtectBatchRequest(StrictModel):
    lease_id: str
    records: list[Any]
    schema_map: dict[str, DataClass]


class ProtectTextRequest(StrictModel):
    lease_id: str
    text: str
    language: str = "en"


class CapabilityRequest(StrictModel):
    lease_id: str
    secret: str
    target: str
    operation: str
    kind: str = "SECRET"


class JobSubmitRequest(StrictModel):
    lease_id: str
    target: str
    operation: str
    payload: dict[str, Any]
    reference_fields: dict[str, DataClass] = {}
    capability_fields: set[str] = set()
    passthrough_fields: set[str] = set()
    response_schema: dict[str, DataClass]
    deadline_seconds: int = Field(default=3600, ge=1, le=86400)
    result_ttl_seconds: int = Field(default=3600, ge=1, le=86400)


class JobResultRequest(StrictModel):
    tenant_id: str | None = None
    agent_id: str | None = None
    purpose: str
    scope: str
    lease_ttl_seconds: int = Field(default=300, ge=1, le=86400)
    allowed_operations: dict[str, list[str]] = {}


def _guard(call: Callable[[], Any]) -> Any:
    try:
        return call()
    except BlueberryError as exc:
        raise HTTPException(status_code=403, detail=exc.safe_detail()) from exc
    except ValueError as exc:
        # Never return str(exc): validation errors may contain input data.
        raise HTTPException(
            status_code=400,
            detail={"code": ErrorCode.BAD_REQUEST.value, "class": "POLICY"},
        ) from exc


def _bad_request() -> HTTPException:
    return HTTPException(status_code=400, detail={"code": ErrorCode.BAD_REQUEST.value, "class": "POLICY"})


def create_app(
    runtime: BlueberryRuntime,
    *,
    api_keys: ApiKeyRegistry | None,
    allow_unauthenticated: bool = False,
) -> FastAPI:
    """Build the gateway.

    `api_keys=None` disables authentication and takes tenant/agent from the request
    body. That mode exists for local development only and must be requested
    explicitly with `allow_unauthenticated=True`.
    """
    if api_keys is None and not allow_unauthenticated:
        raise ValueError("An API key registry is required unless allow_unauthenticated=True")

    guard = StructuredToolGuard(runtime)
    jobs = AsyncJobGateway(runtime)
    app = FastAPI(title="BlueberryMe", version="0.3.0")

    def principal(authorization: str | None = Header(default=None)) -> Principal | None:
        if api_keys is None:
            return None
        token = None
        if authorization:
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer" and value.strip():
                token = value.strip()
        found = api_keys.authenticate(token)
        if found is None:
            raise HTTPException(
                status_code=401,
                detail={"code": ErrorCode.UNAUTHENTICATED.value, "class": "POLICY"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return found

    def require_purpose(p: Principal | None, purpose: str) -> None:
        if p is not None and not p.allows_purpose(purpose):
            raise PolicyDenied(code=ErrorCode.POLICY_DENIED)

    def own_lease(p: Principal | None, lease_id: str) -> None:
        """A key may only use leases of its own tenant (and agent, if bound)."""
        if p is None:
            return
        ident = runtime.lease_identity(lease_id)
        if ident["tenant_id"] != p.tenant_id or (p.agent_id is not None and ident["agent_id"] != p.agent_id):
            # Same code as an unknown lease: do not confirm that the lease exists.
            raise LeaseDenied(code=ErrorCode.LEASE_UNKNOWN)
        require_purpose(p, ident["purpose"])

    def resolve_identity(p: Principal | None, tenant_id: str | None, agent_id: str | None) -> tuple[str, str]:
        if p is None:
            if not agent_id:
                raise _bad_request()
            return tenant_id or "default", agent_id
        if tenant_id is not None and tenant_id != p.tenant_id:
            raise PolicyDenied(code=ErrorCode.POLICY_DENIED)
        if p.agent_id is not None:
            if agent_id is not None and agent_id != p.agent_id:
                raise PolicyDenied(code=ErrorCode.POLICY_DENIED)
            return p.tenant_id, p.agent_id
        if not agent_id:
            raise _bad_request()
        return p.tenant_id, agent_id

    @app.get("/v1/status")
    def status(p: Principal | None = Depends(principal)) -> dict[str, Any]:
        return runtime.status()

    @app.get("/v1/evidence")
    def evidence(p: Principal | None = Depends(principal)) -> dict[str, Any]:
        return runtime.evidence_snapshot()

    @app.post("/v1/leases")
    def create_lease(request: LeaseRequest, p: Principal | None = Depends(principal)) -> dict[str, str]:
        def run() -> dict[str, str]:
            tenant_id, agent_id = resolve_identity(p, request.tenant_id, request.agent_id)
            require_purpose(p, request.purpose)
            return {
                "lease_id": runtime.create_lease(
                    agent_id=agent_id,
                    purpose=request.purpose,
                    scope=request.scope,
                    tenant_id=tenant_id,
                    ttl_seconds=request.ttl_seconds,
                    allowed_operations=request.allowed_operations,
                )
            }

        return _guard(run)

    @app.delete("/v1/leases/{lease_id}")
    def destroy_lease(lease_id: str, p: Principal | None = Depends(principal)) -> dict[str, bool]:
        def run() -> dict[str, bool]:
            if p is not None:
                try:
                    own_lease(p, lease_id)
                except LeaseDenied as exc:
                    if exc.code is ErrorCode.LEASE_EXPIRED:
                        # Expiry already destroyed the lease.
                        return {"destroyed": True}
                    raise
            runtime.destroy_lease(lease_id)
            return {"destroyed": True}

        return _guard(run)

    @app.post("/v1/protect/record")
    def protect_record(request: ProtectRecordRequest, p: Principal | None = Depends(principal)) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            own_lease(p, request.lease_id)
            return {"record": runtime.protect_record(request.record, request.schema_map, request.lease_id)}

        return _guard(run)

    @app.post("/v1/protect/batch")
    def protect_batch(request: ProtectBatchRequest, p: Principal | None = Depends(principal)) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            own_lease(p, request.lease_id)
            return runtime.protect_batch(request.records, request.schema_map, request.lease_id)

        return _guard(run)

    @app.post("/v1/protect/text")
    def protect_text(request: ProtectTextRequest, p: Principal | None = Depends(principal)) -> dict[str, str]:
        def run() -> dict[str, str]:
            own_lease(p, request.lease_id)
            return {"text": runtime.protect_text(request.text, request.lease_id, language=request.language)}

        return _guard(run)

    @app.post("/v1/capabilities")
    def create_capability(request: CapabilityRequest, p: Principal | None = Depends(principal)) -> dict[str, str]:
        def run() -> dict[str, str]:
            own_lease(p, request.lease_id)
            return {
                "handle": runtime.create_capability(
                    request.secret,
                    request.lease_id,
                    target=request.target,
                    operation=request.operation,
                    kind=request.kind,
                )
            }

        return _guard(run)

    @app.post("/v1/jobs")
    def submit_job(request: JobSubmitRequest, p: Principal | None = Depends(principal)) -> dict[str, str]:
        def run() -> dict[str, str]:
            own_lease(p, request.lease_id)
            call = guard.authorize_tool_call(
                request.payload,
                lease_id=request.lease_id,
                target=request.target,
                operation=request.operation,
                reference_fields=request.reference_fields,
                capability_fields=request.capability_fields,
                passthrough_fields=request.passthrough_fields,
            )
            return {
                "job_handle": jobs.submit(
                    call,
                    response_schema=request.response_schema,
                    deadline_seconds=request.deadline_seconds,
                    result_ttl_seconds=request.result_ttl_seconds,
                )
            }

        return _guard(run)

    def _caller(p: Principal | None) -> dict[str, str | None]:
        if p is None:
            return {"tenant_id": None, "agent_id": None}
        return {"tenant_id": p.tenant_id, "agent_id": p.agent_id}

    @app.get("/v1/jobs/{job_handle}")
    def job_status(job_handle: str, p: Principal | None = Depends(principal)) -> dict[str, Any]:
        return _guard(lambda: jobs.status(job_handle, **_caller(p)))

    @app.delete("/v1/jobs/{job_handle}")
    def cancel_job(job_handle: str, p: Principal | None = Depends(principal)) -> dict[str, Any]:
        return _guard(lambda: jobs.cancel(job_handle, **_caller(p)))

    @app.post("/v1/jobs/{job_handle}/result")
    def get_job_result(
        job_handle: str, request: JobResultRequest, p: Principal | None = Depends(principal)
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            tenant_id, agent_id = resolve_identity(p, request.tenant_id, request.agent_id)
            require_purpose(p, request.purpose)
            return jobs.get_result(
                job_handle,
                tenant_id=tenant_id,
                agent_id=agent_id,
                purpose=request.purpose,
                scope=request.scope,
                allowed_operations=request.allowed_operations,
                lease_ttl_seconds=request.lease_ttl_seconds,
                # An agent-bound key only retrieves jobs its own agent submitted.
                submitter_agent_id=p.agent_id if p is not None else None,
            )

        return _guard(run)

    # Intentionally absent:
    # - public /resolve or /rehydrate endpoint
    # - public job-execution endpoint
    # Target execution belongs in the trusted target/worker zone.
    return app


def build_runtime() -> BlueberryRuntime:
    root = Path(__file__).parents[2]
    policy_path = Path(os.environ.get("BBM_POLICY", root / "policies" / "eu-business.yaml"))
    state_dir = Path(os.environ.get("BBM_STATE_DIR", ".blueberryme"))
    state_path = Path(os.environ.get("BBM_STATE_DB", state_dir / "state.db"))
    return BlueberryRuntime(load_policy(policy_path), state_path=state_path)


def create_app_from_env() -> FastAPI:
    """Gateway configured from environment variables.

    BBM_API_KEYS_FILE  YAML file with hashed API keys (required outside dev mode)
    BBM_DEV_MODE=1     without a key file: run unauthenticated (local development only)
    """
    keys_file = os.environ.get("BBM_API_KEYS_FILE")
    if keys_file:
        registry: ApiKeyRegistry | None = ApiKeyRegistry.from_file(keys_file)
    elif dev_mode_enabled():
        registry = None
    else:
        raise RuntimeError(
            "BBM_API_KEYS_FILE is required. Create keys with `blueberryme api-key`, "
            "or set BBM_DEV_MODE=1 to run the gateway unauthenticated for local development."
        )
    return create_app(build_runtime(), api_keys=registry, allow_unauthenticated=registry is None)


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    # `uvicorn blueberryme.api:app` builds the gateway on first access, so importing
    # this module (e.g. for create_app in tests) has no side effects.
    global _app
    if name == "app":
        if _app is None:
            _app = create_app_from_env()
        return _app
    raise AttributeError(name)
