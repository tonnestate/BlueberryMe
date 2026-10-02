from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .errors import BlueberryError
from .jobs import AsyncJobGateway
from .models import DataClass
from .policy import load_policy
from .proxy import StructuredToolGuard
from .runtime import BlueberryRuntime


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
    allowed_operations: dict[str, list[str]] = {}


def build_runtime() -> BlueberryRuntime:
    root = Path(__file__).parents[2]
    policy_path = Path(os.environ.get("BBM_POLICY", root / "policies" / "eu-business.yaml"))
    state_dir = Path(os.environ.get("BBM_STATE_DIR", ".blueberryme"))
    state_path = Path(os.environ.get("BBM_STATE_DB", state_dir / "state.db"))
    return BlueberryRuntime(load_policy(policy_path), state_path=state_path)


runtime = build_runtime()
guard = StructuredToolGuard(runtime)
jobs = AsyncJobGateway(runtime)
app = FastAPI(title="BlueberryMe", version="0.3.0")


def _guard(call):
    try:
        return call()
    except BlueberryError as exc:
        raise HTTPException(status_code=403, detail=exc.safe_detail()) from exc
    except ValueError as exc:
        # Never return str(exc): validation errors may contain input data.
        raise HTTPException(
            status_code=400,
            detail={"code": "BBM_BAD_REQUEST", "class": "POLICY"},
        ) from exc


@app.get("/v1/status")
def status() -> dict[str, Any]:
    return runtime.status()


@app.get("/v1/evidence")
def evidence() -> dict[str, Any]:
    return runtime.evidence_snapshot()


@app.post("/v1/leases")
def create_lease(request: LeaseRequest) -> dict[str, str]:
    return _guard(
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


@app.delete("/v1/leases/{lease_id}")
def destroy_lease(lease_id: str) -> dict[str, bool]:
    runtime.destroy_lease(lease_id)
    return {"destroyed": True}


@app.post("/v1/protect/record")
def protect_record(request: ProtectRecordRequest) -> dict[str, Any]:
    return {"record": _guard(lambda: runtime.protect_record(request.record, request.schema_map, request.lease_id))}


@app.post("/v1/protect/batch")
def protect_batch(request: ProtectBatchRequest) -> dict[str, Any]:
    return _guard(lambda: runtime.protect_batch(request.records, request.schema_map, request.lease_id))


@app.post("/v1/protect/text")
def protect_text(request: ProtectTextRequest) -> dict[str, str]:
    return {"text": _guard(lambda: runtime.protect_text(request.text, request.lease_id, language=request.language))}


@app.post("/v1/capabilities")
def create_capability(request: CapabilityRequest) -> dict[str, str]:
    return _guard(
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


@app.post("/v1/jobs")
def submit_job(request: JobSubmitRequest) -> dict[str, str]:
    def submit() -> dict[str, str]:
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

    return _guard(submit)


@app.get("/v1/jobs/{job_handle}")
def job_status(job_handle: str) -> dict[str, Any]:
    return _guard(lambda: jobs.status(job_handle))


@app.delete("/v1/jobs/{job_handle}")
def cancel_job(job_handle: str) -> dict[str, Any]:
    return _guard(lambda: jobs.cancel(job_handle))


@app.post("/v1/jobs/{job_handle}/result")
def get_job_result(job_handle: str, request: JobResultRequest) -> dict[str, Any]:
    return _guard(
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
