"""HTTP gateway for BBM/1.

Two planes, two credentials:

* **Control plane** (``BBM_CONTROL_TOKEN``): the trusted orchestrator. Creates and
  destroys leases, protects ingress data, registers capabilities, reads evidence.
  Lease creation *is* the authority root, so it must never be reachable with an
  agent credential.
* **Agent plane** (``BBM_AGENT_TOKENS="agent-a=<token>,agent-b=<token>"``): untrusted
  agents. Submit jobs with handles, poll, cancel and fetch re-tokenised results. The
  agent identity comes from the token, never from the request body.

Without configured tokens the gateway fails closed (HTTP 503). ``BBM_INSECURE_DEV=1``
disables authentication for local experiments only.
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .errors import BlueberryError
from .jobs import AsyncJobGateway
from .models import DataClass
from .policy import load_policy
from .proxy import StructuredToolGuard
from .runtime import BlueberryRuntime

MIN_TOKEN_LENGTH = 32


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LeaseRequest(StrictModel):
    agent_id: str
    purpose: str
    scope: str
    tenant_id: str = "default"
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
    tenant_id: str = "default"
    agent_id: str
    purpose: str
    scope: str
    lease_ttl_seconds: int = Field(default=300, ge=1, le=86400)
    # Omitted -> the submitting lease's operations. Never more than those.
    allowed_operations: dict[str, list[str]] | None = None


@dataclass(frozen=True)
class GatewayAuth:
    control_token: str | None = None
    agent_tokens: dict[str, str] = field(default_factory=dict)  # token -> agent_id
    insecure_dev: bool = False

    def __post_init__(self) -> None:
        tokens = ([self.control_token] if self.control_token else []) + list(self.agent_tokens)
        for token in tokens:
            if len(token) < MIN_TOKEN_LENGTH:
                raise ValueError(f"Gateway tokens must be at least {MIN_TOKEN_LENGTH} characters")
        if self.control_token and self.control_token in self.agent_tokens:
            raise ValueError("Control and agent tokens must differ")

    @classmethod
    def from_env(cls) -> "GatewayAuth":
        agents: dict[str, str] = {}
        for item in filter(None, (x.strip() for x in os.environ.get("BBM_AGENT_TOKENS", "").split(","))):
            agent_id, sep, token = item.partition("=")
            if not sep or not agent_id.strip() or not token.strip():
                raise ValueError("BBM_AGENT_TOKENS must look like 'agent-a=<token>,agent-b=<token>'")
            agents[token.strip()] = agent_id.strip()
        return cls(
            control_token=os.environ.get("BBM_CONTROL_TOKEN") or None,
            agent_tokens=agents,
            insecure_dev=os.environ.get("BBM_INSECURE_DEV") == "1",
        )

    @staticmethod
    def _bearer(authorization: str | None) -> str | None:
        if not authorization:
            return None
        scheme, _, token = authorization.partition(" ")
        return token.strip() if scheme.lower() == "bearer" and token.strip() else None

    def control(self, authorization: str | None) -> None:
        if self.control_token is None:
            if self.insecure_dev:
                return
            raise HTTPException(status_code=503, detail={"code": "BBM_GATEWAY_NOT_CONFIGURED", "class": "INFRASTRUCTURE"})
        token = self._bearer(authorization)
        if token is None or not hmac.compare_digest(token.encode(), self.control_token.encode()):
            raise HTTPException(status_code=401, detail={"code": "BBM_UNAUTHENTICATED", "class": "POLICY"})

    def agent(self, authorization: str | None) -> str | None:
        """Returns the authenticated agent id, or None in insecure dev mode."""
        if not self.agent_tokens:
            if self.insecure_dev:
                return None
            raise HTTPException(status_code=503, detail={"code": "BBM_GATEWAY_NOT_CONFIGURED", "class": "INFRASTRUCTURE"})
        token = self._bearer(authorization)
        found: str | None = None
        if token is not None:
            # Compare against every token so timing does not reveal which prefix matched.
            for known, agent_id in self.agent_tokens.items():
                if hmac.compare_digest(token.encode(), known.encode()):
                    found = agent_id
        if found is None:
            raise HTTPException(status_code=401, detail={"code": "BBM_UNAUTHENTICATED", "class": "POLICY"})
        return found


def build_runtime() -> BlueberryRuntime:
    root = Path(__file__).parents[2]
    policy_path = Path(os.environ.get("BBM_POLICY", root / "policies" / "eu-business.yaml"))
    state_dir = Path(os.environ.get("BBM_STATE_DIR", ".blueberryme"))
    state_path = Path(os.environ.get("BBM_STATE_DB", state_dir / "state.db"))
    return BlueberryRuntime(load_policy(policy_path), state_path=state_path)


def _forbidden(code: str) -> HTTPException:
    return HTTPException(status_code=403, detail={"code": code, "class": "POLICY"})


def create_app(runtime: BlueberryRuntime | None = None, auth: GatewayAuth | None = None) -> FastAPI:
    runtime = runtime or build_runtime()
    auth = auth or GatewayAuth.from_env()
    guard = StructuredToolGuard(runtime)
    jobs = AsyncJobGateway(runtime)
    app = FastAPI(title="BlueberryMe", version="0.3.1")

    def control(authorization: str | None = Header(default=None)) -> None:
        auth.control(authorization)

    def agent(authorization: str | None = Header(default=None)) -> str | None:
        return auth.agent(authorization)

    def run(call: Callable[[], Any]) -> Any:
        try:
            return call()
        except BlueberryError as exc:
            raise HTTPException(status_code=403, detail=exc.safe_detail()) from exc
        except ValueError as exc:
            # Never return str(exc): validation errors may contain input data.
            raise HTTPException(status_code=400, detail={"code": "BBM_BAD_REQUEST", "class": "POLICY"}) from exc

    # ---------------------------------------------------------- control plane

    @app.get("/v1/status", dependencies=[Depends(control)])
    def status() -> dict[str, Any]:
        return runtime.status()

    @app.get("/v1/evidence", dependencies=[Depends(control)])
    def evidence() -> dict[str, Any]:
        return runtime.evidence_snapshot()

    @app.post("/v1/leases", dependencies=[Depends(control)])
    def create_lease(request: LeaseRequest) -> dict[str, str]:
        return run(
            lambda: {
                "lease_id": runtime.create_lease(
                    agent_id=request.agent_id,
                    purpose=request.purpose,
                    scope=request.scope,
                    tenant_id=request.tenant_id,
                    ttl_seconds=request.ttl_seconds,
                    allowed_operations=request.allowed_operations,
                )
            }
        )

    @app.delete("/v1/leases/{lease_id}", dependencies=[Depends(control)])
    def destroy_lease(lease_id: str) -> dict[str, bool]:
        runtime.destroy_lease(lease_id)
        return {"destroyed": True}

    @app.post("/v1/protect/record", dependencies=[Depends(control)])
    def protect_record(request: ProtectRecordRequest) -> dict[str, Any]:
        return {"record": run(lambda: runtime.protect_record(request.record, request.schema_map, request.lease_id))}

    @app.post("/v1/protect/batch", dependencies=[Depends(control)])
    def protect_batch(request: ProtectBatchRequest) -> dict[str, Any]:
        return run(lambda: runtime.protect_batch(request.records, request.schema_map, request.lease_id))

    @app.post("/v1/protect/text", dependencies=[Depends(control)])
    def protect_text(request: ProtectTextRequest) -> dict[str, str]:
        return {"text": run(lambda: runtime.protect_text(request.text, request.lease_id, language=request.language))}

    @app.post("/v1/capabilities", dependencies=[Depends(control)])
    def create_capability(request: CapabilityRequest) -> dict[str, str]:
        return run(
            lambda: {
                "handle": runtime.create_capability(
                    request.secret,
                    request.lease_id,
                    target=request.target,
                    operation=request.operation,
                    kind=request.kind,
                )
            }
        )

    # ------------------------------------------------------------ agent plane

    @app.post("/v1/jobs")
    def submit_job(request: JobSubmitRequest, agent_id: str | None = Depends(agent)) -> dict[str, str]:
        def submit() -> dict[str, str]:
            _, lease_agent = runtime.lease_owner(request.lease_id)
            if agent_id is not None and lease_agent != agent_id:
                raise _forbidden("BBM_AGENT_MISMATCH")
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

        return run(submit)

    @app.get("/v1/jobs/{job_handle}")
    def job_status(job_handle: str, agent_id: str | None = Depends(agent)) -> dict[str, Any]:
        return run(lambda: jobs.status(job_handle, agent_id=agent_id))

    @app.delete("/v1/jobs/{job_handle}")
    def cancel_job(job_handle: str, agent_id: str | None = Depends(agent)) -> dict[str, Any]:
        return run(lambda: jobs.cancel(job_handle, agent_id=agent_id))

    @app.post("/v1/jobs/{job_handle}/result")
    def get_job_result(
        job_handle: str, request: JobResultRequest, agent_id: str | None = Depends(agent)
    ) -> dict[str, Any]:
        if agent_id is not None and request.agent_id != agent_id:
            raise _forbidden("BBM_AGENT_MISMATCH")
        return run(
            lambda: jobs.get_result(
                job_handle,
                tenant_id=request.tenant_id,
                agent_id=request.agent_id,
                purpose=request.purpose,
                scope=request.scope,
                allowed_operations=request.allowed_operations,
                lease_ttl_seconds=request.lease_ttl_seconds,
            )
        )

    # Intentionally absent:
    # - public /resolve or /rehydrate endpoint
    # - public job-execution endpoint
    # Target execution belongs in the trusted target/worker zone.
    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    # ``uvicorn blueberryme.api:app`` keeps working, but importing this module no
    # longer creates state files or reads credentials as a side effect.
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
