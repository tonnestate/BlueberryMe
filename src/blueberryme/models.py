from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class DataClass(StrEnum):
    UNKNOWN = "UNKNOWN"
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ADDRESS = "ADDRESS"
    CASE_ID = "CASE_ID"
    BIRTH_DATE = "BIRTH_DATE"
    IBAN = "IBAN"
    SECRET = "SECRET"
    HEALTH_DATA = "HEALTH_DATA"
    PUBLIC = "PUBLIC"


class Transform(StrEnum):
    ALLOW = "ALLOW"
    TOKENIZE = "TOKENIZE"
    DENY = "DENY"


class TokenMode(StrEnum):
    LEASE_HANDLE = "LEASE_HANDLE"


class Linkability(StrEnum):
    """Whether repeated occurrences of one value share a handle.

    LEASE: same value (or same source pointer) -> same handle inside one lease, so the
    agent can reason about "the same customer" across records. Different leases stay
    unlinkable. OCCURRENCE: every occurrence gets a fresh handle (maximum unlinkability,
    weaker agent reasoning).
    """

    LEASE = "LEASE"
    OCCURRENCE = "OCCURRENCE"


class QualityAction(StrEnum):
    KEEP_NULL = "KEEP_NULL"
    KEEP_EMPTY = "KEEP_EMPTY"
    KEEP_VALUE = "KEEP_VALUE"
    PROTECT = "PROTECT"
    SUPPRESS = "SUPPRESS"
    ERROR = "ERROR"


class FailureClass(StrEnum):
    DATA_QUALITY = "DATA_QUALITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    REHYDRATION = "REHYDRATION"
    POLICY = "POLICY"


class ReferenceKind(StrEnum):
    CAPSULE = "CAPSULE"
    SOURCE = "SOURCE"
    CAPABILITY = "CAPABILITY"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    RETRIEVED = "RETRIEVED"


@dataclass(frozen=True)
class QualityPolicy:
    on_null: QualityAction = QualityAction.KEEP_NULL
    on_empty: QualityAction = QualityAction.KEEP_EMPTY
    on_invalid: QualityAction = QualityAction.PROTECT
    on_transform_error: QualityAction = QualityAction.SUPPRESS
    accepted_birth_date_formats: tuple[str, ...] = ("%Y-%m-%d",)


@dataclass(frozen=True)
class ClassPolicy:
    action: Transform
    token_mode: TokenMode = TokenMode.LEASE_HANDLE
    linkability: Linkability = Linkability.LEASE
    rehydrate: dict[str, frozenset[str]] = field(default_factory=dict)
    allowed_purposes: frozenset[str] = frozenset()
    quality: QualityPolicy = QualityPolicy()


@dataclass(frozen=True)
class FlowRule:
    origin_scope: str
    sinks: dict[str, frozenset[str]]
    purposes: frozenset[str] = frozenset()


@dataclass
class Lease:
    lease_id: str
    tenant_id: str
    agent_id: str
    purpose: str
    scope: str
    expires_at: datetime
    allowed_operations: dict[str, frozenset[str]]
    revoked: bool = False


@dataclass(frozen=True)
class SourceReference:
    source_id: str
    record_key: str
    field: str
    row_version: str | None = None


@dataclass(frozen=True)
class HandleEntry:
    handle: str
    lease_id: str
    data_class: DataClass
    origin_scope: str
    reference_id: str
    kind: ReferenceKind
    target: str | None = None
    operation: str | None = None


@dataclass(frozen=True)
class ResolutionIntent:
    intent_id: str
    call_id: str
    lease_id: str
    target: str
    operation: str
    purpose: str
    handles: tuple[str, ...]
    args_hash: str
    policy_version: str
    expires_at: str
    signature: str
    # Hash of the declared field -> data-class map. Binds *how* the payload may be
    # resolved, not only *what* the payload is.
    fields_hash: str = ""


@dataclass(frozen=True)
class JobIntent:
    intent_id: str
    job_id: str
    tenant_id: str
    purpose: str
    target: str
    operation: str
    envelope_hash: str
    policy_version: str
    expires_at: str
    signature: str


@dataclass(frozen=True)
class GuardedCall:
    lease_id: str
    target: str
    operation: str
    payload: dict[str, Any]
    reference_fields: dict[str, DataClass]
    capability_fields: frozenset[str]
    passthrough_fields: frozenset[str]
    intent: ResolutionIntent


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event_type: str
    lease_ref: str
    agent_ref: str
    purpose: str
    scope_ref: str
    retention_epoch: str
    data_class: str | None = None
    decision: str | None = None
    count: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)
