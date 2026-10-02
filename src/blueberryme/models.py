from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class DataClass(StrEnum):
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
    GENERALIZE = "GENERALIZE"
    DENY = "DENY"


class TokenMode(StrEnum):
    CRYPTO_TOKEN = "CRYPTO_TOKEN"
    LEASE_HANDLE = "LEASE_HANDLE"


class QualityAction(StrEnum):
    KEEP_NULL = "KEEP_NULL"
    KEEP_EMPTY = "KEEP_EMPTY"
    KEEP_VALUE = "KEEP_VALUE"
    SUPPRESS = "SUPPRESS"
    ERROR = "ERROR"


@dataclass(frozen=True)
class QualityPolicy:
    on_null: QualityAction = QualityAction.KEEP_NULL
    on_empty: QualityAction = QualityAction.KEEP_EMPTY
    on_invalid: QualityAction = QualityAction.SUPPRESS
    on_transform_error: QualityAction = QualityAction.SUPPRESS
    accepted_birth_date_formats: tuple[str, ...] = ("%Y-%m-%d",)


@dataclass(frozen=True)
class ClassPolicy:
    action: Transform
    token_mode: TokenMode = TokenMode.LEASE_HANDLE
    rehydrate: dict[str, frozenset[str]] = field(default_factory=dict)
    allowed_purposes: frozenset[str] = frozenset()
    quality: QualityPolicy = QualityPolicy()


@dataclass
class Lease:
    lease_id: str
    agent_id: str
    purpose: str
    scope: str
    expires_at: datetime
    key: bytearray
    allowed_operations: dict[str, frozenset[str]]
    revoked: bool = False
    capabilities: set[str] = field(default_factory=set)
    handles: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event_type: str
    lease_ref: str
    agent_ref: str
    purpose: str
    scope_ref: str
    data_class: str | None = None
    decision: str | None = None
    count: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)
