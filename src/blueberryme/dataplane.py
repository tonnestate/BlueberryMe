from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence

from .models import DataClass
from .policy import Policy


class DataPlaneMode(StrEnum):
    BATCH_PROTECT = "BATCH_PROTECT"
    PUSH_DOWN_AGGREGATE = "PUSH_DOWN_AGGREGATE"


@dataclass(frozen=True)
class CompiledSchemaPlan:
    classes: Mapping[str, DataClass]
    fingerprint: str
    policy_version: str


@dataclass(frozen=True)
class DataPlanePlan:
    mode: DataPlaneMode
    emit_row_handles: bool
    chunk_size: int
    reason: str


def compile_schema(policy: Policy, schema: Mapping[str, DataClass | str]) -> CompiledSchemaPlan:
    classes = {str(field): (declared if isinstance(declared, DataClass) else DataClass(declared)) for field, declared in schema.items()}
    canonical = json.dumps({field: data_class.value for field, data_class in sorted(classes.items())}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fingerprint = hashlib.sha256(policy.version.encode("utf-8") + b"\0" + canonical).hexdigest()
    return CompiledSchemaPlan(classes=classes, fingerprint=fingerprint, policy_version=policy.version)


def plan_data_plane(*, estimated_rows: int, aggregate_query: bool, entity_references_required: bool, pushdown_threshold: int = 10_000, chunk_size: int = 1_000) -> DataPlanePlan:
    if estimated_rows < 0:
        raise ValueError("estimated_rows must be >= 0")
    if pushdown_threshold < 1 or chunk_size < 1:
        raise ValueError("threshold and chunk_size must be positive")
    if aggregate_query and not entity_references_required and estimated_rows >= pushdown_threshold:
        return DataPlanePlan(DataPlaneMode.PUSH_DOWN_AGGREGATE, False, chunk_size, "aggregate result can stay behind the boundary until reduced")
    return DataPlanePlan(DataPlaneMode.BATCH_PROTECT, True, chunk_size, "row-level agent references are required or result is below pushdown threshold")


def protect_compiled_batch(runtime: Any, records: Sequence[Any], plan: CompiledSchemaPlan, lease_id: str, *, chunk_size: int = 1_000) -> dict[str, Any]:
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    protected: list[dict[str, Any]] = []
    quarantined: list[int] = []
    offset = 0
    for start in range(0, len(records), chunk_size):
        chunk = records[start : start + chunk_size]
        result = runtime.protect_batch(chunk, plan.classes, lease_id)
        protected.extend(result["records"])
        quarantined.extend(offset + index for index in result["quarantined_indexes"])
        offset += len(chunk)
    return {
        "records": protected,
        "input_count": len(records),
        "output_count": len(protected),
        "quarantined_count": len(quarantined),
        "quarantined_indexes": quarantined,
        "schema_fingerprint": plan.fingerprint,
        "policy_version": plan.policy_version,
    }
