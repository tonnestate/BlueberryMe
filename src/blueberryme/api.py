from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .errors import BlueberryError
from .models import DataClass
from .policy import load_policy
from .proxy import StructuredToolGuard
from .runtime import BlueberryRuntime

_POLICY_PATH = Path(os.environ.get("BBM_POLICY", Path(__file__).parents[2] / "policies" / "eu-business.yaml"))
runtime = BlueberryRuntime(load_policy(_POLICY_PATH))
tool_guard = StructuredToolGuard(runtime)
app = FastAPI(title="BlueberryMe", version="0.2.0")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LeaseRequest(StrictModel):
    agent_id: str
    purpose: str
    scope: str
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


class RehydrateRequest(StrictModel):
    lease_id: str
    reference: str
    target: str
    operation: str
    expected_class: DataClass


class CapabilityRequest(StrictModel):
    lease_id: str
    secret: str
    target: str
    operation: str
    kind: str = "SECRET"


class CapabilityResolveRequest(StrictModel):
    lease_id: str
    handle: str
    target: str
    operation: str


def _guard(call):
    try:
        return call()
    except BlueberryError as exc:
        raise HTTPException(status_code=403, detail=exc.safe_detail()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"code": "BBM_BAD_REQUEST", "message": str(exc)}) from exc


@app.get("/v1/status")
def status() -> dict[str, Any]:
    return runtime.status()


@app.get("/v1/evidence")
def evidence() -> dict[str, Any]:
    return runtime.evidence_snapshot()


@app.post("/v1/leases")
def create_lease(request: LeaseRequest) -> dict[str, str]:
    return {
        "lease_id": runtime.create_lease(
            agent_id=request.agent_id,
            purpose=request.purpose,
            scope=request.scope,
            ttl_seconds=request.ttl_seconds,
            allowed_operations=request.allowed_operations,
        )
    }


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


@app.post("/v1/rehydrate")
def rehydrate(request: RehydrateRequest) -> dict[str, str]:
    return {
        "value": _guard(
            lambda: runtime.rehydrate_reference(
                request.reference,
                request.lease_id,
                target=request.target,
                operation=request.operation,
                expected_class=request.expected_class,
            )
        )
    }


@app.post("/v1/capabilities")
def create_capability(request: CapabilityRequest) -> dict[str, str]:
    return {
        "handle": _guard(
            lambda: runtime.create_capability(
                request.secret,
                request.lease_id,
                target=request.target,
                operation=request.operation,
                kind=request.kind,
            )
        )
    }


@app.post("/v1/capabilities/resolve")
def resolve_capability(request: CapabilityResolveRequest) -> dict[str, str]:
    return {
        "secret": _guard(
            lambda: runtime.resolve_capability(
                request.handle,
                request.lease_id,
                target=request.target,
                operation=request.operation,
            )
        )
    }
