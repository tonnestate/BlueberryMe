from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from .crypto import CAPABILITY_RE, HANDLE_RE, CryptoError, parse_handle, random_capability_handle, random_handle
from .detectors import Finding, RegexDetector
from .errors import (
    BlueberryError,
    CapabilityDenied,
    DataQualityError,
    ErrorCode,
    LeaseDenied,
    PolicyDenied,
    RehydrationError,
)
from .intents import IntentAuthority
from .keys import load_or_create_master_key, subkeys
from .models import (
    AuditEvent,
    DataClass,
    GuardedCall,
    HandleEntry,
    Lease,
    QualityAction,
    ReferenceKind,
    ResolutionIntent,
    SourceReference,
    Transform,
)
from .policy import Policy
from .references import ExportedReference, ReferenceStore, SourceAdapter, SourceRegistry, resolve_exported
from .storage import MemoryStateBackend, SecureState, SQLiteStateBackend, StateBackend
from .validators import is_valid

_SUPPRESSED = object()


class BlueberryRuntime:
    """BBM/1 v0.3 reference runtime.

    The agent sees random lease-local handles only. Sensitive values and encrypted
    references remain inside the BlueberryMe boundary. There is intentionally no
    public general-purpose decode method.
    """

    LEASE_KIND = "lease"
    HANDLE_KIND = "handle"
    REVOCATION_KIND = "revoked-purpose"

    def __init__(
        self,
        policy: Policy,
        detector: Any | None = None,
        *,
        state_backend: StateBackend | None = None,
        state_path: str | Path | None = None,
        master_key: bytes | None = None,
        state_dir: str | Path | None = None,
    ) -> None:
        self.policy = policy
        self.detector = detector or RegexDetector()
        if state_backend is not None and state_path is not None:
            raise ValueError("Use state_backend or state_path, not both")
        if state_backend is None:
            state_backend = SQLiteStateBackend(state_path) if state_path is not None else MemoryStateBackend()
        if master_key is None:
            if state_path is not None:
                master_key = load_or_create_master_key(Path(state_path).parent)
            elif state_dir is not None:
                master_key = load_or_create_master_key(state_dir)
            else:
                master_key = secrets.token_bytes(32)
        if len(master_key) != 32:
            raise ValueError("master_key must be exactly 32 bytes")

        self._backend = state_backend
        self._master_key = bytes(master_key)
        self._keys = subkeys(self._master_key)
        self._state = SecureState(self._backend, self._keys["state"])
        self._references = ReferenceStore(self._state)
        self._sources = SourceRegistry()
        self._intent_authority = IntentAuthority(self._keys["intent"], self._backend)
        self._metrics: Counter[str] = Counter()
        self._lock = threading.RLock()

    @classmethod
    def persistent(
        cls,
        policy: Policy,
        state_path: str | Path,
        *,
        detector: Any | None = None,
        master_key: bytes | None = None,
    ) -> "BlueberryRuntime":
        return cls(policy, detector, state_path=state_path, master_key=master_key)

    @property
    def intent_authority(self) -> IntentAuthority:
        return self._intent_authority

    @property
    def secure_state(self) -> SecureState:
        return self._state

    def register_source(self, source_id: str, adapter: SourceAdapter) -> None:
        self._sources.register(source_id, adapter)

    @staticmethod
    def _purpose_key(tenant_id: str, purpose: str) -> str:
        return hashlib.sha256(f"{tenant_id}\x00{purpose}".encode("utf-8")).hexdigest()

    def revoke_purpose(self, tenant_id: str, purpose: str) -> None:
        key = self._purpose_key(tenant_id, purpose)
        self._state.put_json(self.REVOCATION_KIND, key, {"tenant_id": tenant_id, "purpose": purpose})

    def restore_purpose(self, tenant_id: str, purpose: str) -> None:
        self._state.delete(self.REVOCATION_KIND, self._purpose_key(tenant_id, purpose))

    def purpose_active(self, tenant_id: str, purpose: str) -> bool:
        return self._state.get_json(self.REVOCATION_KIND, self._purpose_key(tenant_id, purpose)) is None

    @staticmethod
    def _retention_epoch() -> str:
        now = datetime.now(UTC)
        return f"{now.year:04d}-{now.month:02d}"

    def _audit_ref(self, lease: Lease, value: str) -> str:
        epoch = self._retention_epoch()
        scoped = hmac.new(
            self._keys["audit"],
            f"{lease.tenant_id}|{lease.purpose}|{epoch}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return hmac.new(scoped, value.encode("utf-8"), hashlib.sha256).hexdigest()[:20]

    def _audit_event(
        self,
        event_type: str,
        lease: Lease,
        *,
        data_class: DataClass | None = None,
        decision: str | None = None,
        count: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        safe_metadata = dict(metadata or {})
        forbidden = {"value", "raw", "plaintext", "ciphertext", "token", "secret", "resolved", "payload", "handle"}
        if forbidden.intersection(k.lower() for k in safe_metadata):
            raise BlueberryError("Sensitive audit metadata key rejected")
        event = AuditEvent(
            timestamp=datetime.now(UTC).isoformat(),
            event_type=event_type,
            lease_ref=self._audit_ref(lease, lease.lease_id),
            agent_ref=self._audit_ref(lease, lease.agent_id),
            purpose=lease.purpose,
            scope_ref=self._audit_ref(lease, lease.scope),
            retention_epoch=self._retention_epoch(),
            data_class=data_class.value if data_class else None,
            decision=decision,
            count=count,
            metadata=safe_metadata,
        )
        self._backend.append_audit(event.__dict__)
        self._metrics[f"{event_type}:{decision or 'NONE'}"] += count

    @staticmethod
    def _normalise_operations(allowed_operations: Mapping[str, Sequence[str]] | None) -> dict[str, frozenset[str]]:
        return {
            str(target): frozenset(str(op) for op in operations)
            for target, operations in (allowed_operations or {}).items()
        }

    @staticmethod
    def _lease_to_json(lease: Lease) -> dict[str, Any]:
        return {
            "lease_id": lease.lease_id,
            "tenant_id": lease.tenant_id,
            "agent_id": lease.agent_id,
            "purpose": lease.purpose,
            "scope": lease.scope,
            "expires_at": lease.expires_at.isoformat(),
            "allowed_operations": {k: sorted(v) for k, v in lease.allowed_operations.items()},
            "revoked": lease.revoked,
            "handles": sorted(lease.handles),
            "reference_ids": sorted(lease.reference_ids),
        }

    @staticmethod
    def _lease_from_json(item: dict[str, Any]) -> Lease:
        return Lease(
            lease_id=str(item["lease_id"]),
            tenant_id=str(item["tenant_id"]),
            agent_id=str(item["agent_id"]),
            purpose=str(item["purpose"]),
            scope=str(item["scope"]),
            expires_at=datetime.fromisoformat(str(item["expires_at"])),
            allowed_operations={str(k): frozenset(str(x) for x in v) for k, v in item["allowed_operations"].items()},
            revoked=bool(item.get("revoked", False)),
            handles=set(str(x) for x in item.get("handles", [])),
            reference_ids=set(str(x) for x in item.get("reference_ids", [])),
        )

    def _save_lease(self, lease: Lease) -> None:
        self._state.put_json(self.LEASE_KIND, lease.lease_id, self._lease_to_json(lease))

    def _load_lease(self, lease_id: str) -> Lease | None:
        item = self._state.get_json(self.LEASE_KIND, lease_id)
        return None if item is None else self._lease_from_json(item)

    def create_lease(
        self,
        *,
        agent_id: str,
        purpose: str,
        scope: str,
        tenant_id: str = "default",
        ttl_seconds: int = 300,
        allowed_operations: Mapping[str, Sequence[str]] | None = None,
    ) -> str:
        if not agent_id or not purpose or not scope or not tenant_id:
            raise ValueError("agent_id, purpose, scope and tenant_id are required")
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise ValueError("ttl_seconds must be between 1 and 86400")
        if not self.purpose_active(tenant_id, purpose):
            raise PolicyDenied(code=ErrorCode.PURPOSE_REVOKED)
        lease = Lease(
            lease_id="BBM1-LEASE-" + secrets.token_urlsafe(18),
            tenant_id=tenant_id,
            agent_id=agent_id,
            purpose=purpose,
            scope=scope,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            allowed_operations=self._normalise_operations(allowed_operations),
        )
        with self._lock:
            self._save_lease(lease)
            self._audit_event("LEASE_CREATED", lease, decision="ALLOW")
        return lease.lease_id

    def _active_lease(self, lease_id: str) -> Lease:
        with self._lock:
            lease = self._load_lease(lease_id)
            if lease is None:
                raise LeaseDenied(code=ErrorCode.LEASE_UNKNOWN)
            if lease.revoked:
                raise LeaseDenied(code=ErrorCode.LEASE_REVOKED)
            if datetime.now(UTC) >= lease.expires_at:
                self._destroy_locked(lease)
                raise LeaseDenied(code=ErrorCode.LEASE_EXPIRED)
            if not self.purpose_active(lease.tenant_id, lease.purpose):
                raise PolicyDenied(code=ErrorCode.PURPOSE_REVOKED)
            return lease

    @staticmethod
    def _operation_allowed(lease: Lease, target: str, operation: str) -> bool:
        allowed = lease.allowed_operations.get(target, frozenset())
        return operation in allowed or "*" in allowed

    @staticmethod
    def _entry_to_json(entry: HandleEntry) -> dict[str, Any]:
        return {
            "handle": entry.handle,
            "lease_id": entry.lease_id,
            "data_class": entry.data_class.value,
            "origin_scope": entry.origin_scope,
            "reference_id": entry.reference_id,
            "kind": entry.kind.value,
            "target": entry.target,
            "operation": entry.operation,
        }

    @staticmethod
    def _entry_from_json(item: dict[str, Any]) -> HandleEntry:
        return HandleEntry(
            handle=str(item["handle"]),
            lease_id=str(item["lease_id"]),
            data_class=DataClass(item["data_class"]),
            origin_scope=str(item["origin_scope"]),
            reference_id=str(item["reference_id"]),
            kind=ReferenceKind(item["kind"]),
            target=item.get("target"),
            operation=item.get("operation"),
        )

    def _load_entry(self, handle: str) -> HandleEntry | None:
        item = self._state.get_json(self.HANDLE_KIND, handle)
        return None if item is None else self._entry_from_json(item)

    def _new_handle(
        self,
        *,
        lease: Lease,
        data_class: DataClass,
        reference_id: str,
        kind: ReferenceKind,
        origin_scope: str | None = None,
        target: str | None = None,
        operation: str | None = None,
    ) -> str:
        for _ in range(32):
            handle = random_capability_handle() if kind is ReferenceKind.CAPABILITY else random_handle(data_class)
            if self._state.get_json(self.HANDLE_KIND, handle) is None:
                break
        else:
            raise BlueberryError("Unable to allocate collision-free handle")
        entry = HandleEntry(
            handle=handle,
            lease_id=lease.lease_id,
            data_class=data_class,
            origin_scope=origin_scope or lease.scope,
            reference_id=reference_id,
            kind=kind,
            target=target,
            operation=operation,
        )
        self._state.put_json(self.HANDLE_KIND, handle, self._entry_to_json(entry), expires_at=lease.expires_at.timestamp())
        lease.handles.add(handle)
        lease.reference_ids.add(reference_id)
        self._save_lease(lease)
        return handle

    def _new_reference_id(self) -> str:
        return "BBM1-REF-" + secrets.token_urlsafe(18)

    def _store_capsule(
        self,
        value: Any,
        *,
        lease: Lease,
        data_class: DataClass,
        kind: ReferenceKind = ReferenceKind.CAPSULE,
        target: str | None = None,
        operation: str | None = None,
        origin_scope: str | None = None,
    ) -> str:
        reference_id = self._new_reference_id()
        self._references.put_capsule(
            reference_id,
            value,
            lease_id=lease.lease_id,
            data_class=data_class,
            kind=kind,
            expires_at=lease.expires_at.timestamp(),
        )
        return self._new_handle(
            lease=lease,
            data_class=data_class,
            reference_id=reference_id,
            kind=kind,
            origin_scope=origin_scope,
            target=target,
            operation=operation,
        )

    def _store_source_reference(
        self,
        reference: SourceReference,
        *,
        lease: Lease,
        data_class: DataClass,
        origin_scope: str | None = None,
    ) -> str:
        reference_id = self._new_reference_id()
        self._references.put_source(
            reference_id,
            reference,
            lease_id=lease.lease_id,
            data_class=data_class,
            expires_at=lease.expires_at.timestamp(),
        )
        return self._new_handle(
            lease=lease,
            data_class=data_class,
            reference_id=reference_id,
            kind=ReferenceKind.SOURCE,
            origin_scope=origin_scope,
        )

    def _protect_without_validation(self, value: Any, data_class: DataClass, lease: Lease) -> Any:
        rule = self.policy.for_class(data_class, lease.purpose)
        if rule.action is Transform.ALLOW:
            self._audit_event("PROTECT", lease, data_class=data_class, decision="ALLOW")
            return value
        if rule.action is Transform.DENY:
            self._audit_event("PROTECT", lease, data_class=data_class, decision="DENY")
            return _SUPPRESSED
        if rule.action is Transform.TOKENIZE:
            handle = self._store_capsule(value, lease=lease, data_class=data_class)
            self._audit_event("PROTECT", lease, data_class=data_class, decision="RANDOM_HANDLE")
            return handle
        raise PolicyDenied("Unsupported transformation")

    def _apply_quality_action(
        self,
        *,
        action: QualityAction,
        value: Any,
        lease: Lease,
        data_class: DataClass,
        reason: str,
    ) -> Any:
        self._audit_event("DATA_QUALITY", lease, data_class=data_class, decision=f"{reason}_{action.value}")
        if action is QualityAction.KEEP_NULL:
            return None
        if action is QualityAction.KEEP_EMPTY:
            return ""
        if action is QualityAction.KEEP_VALUE:
            return value
        if action is QualityAction.PROTECT:
            return self._protect_without_validation(value, data_class, lease)
        if action is QualityAction.SUPPRESS:
            return _SUPPRESSED
        raise DataQualityError()

    def protect_value(self, value: Any, data_class: DataClass, lease_id: str) -> Any:
        lease = self._active_lease(lease_id)
        protected = self._protect_without_validation(value, data_class, lease)
        return None if protected is _SUPPRESSED else protected

    def protect_source_reference(
        self,
        reference: SourceReference,
        data_class: DataClass,
        lease_id: str,
        *,
        origin_scope: str | None = None,
    ) -> Any:
        lease = self._active_lease(lease_id)
        rule = self.policy.for_class(data_class, lease.purpose)
        if rule.action is Transform.ALLOW:
            value = self._sources.read(reference, enforce_version=True)
            self._audit_event("PROTECT_SOURCE", lease, data_class=data_class, decision="ALLOW")
            return value
        if rule.action is Transform.DENY:
            self._audit_event("PROTECT_SOURCE", lease, data_class=data_class, decision="DENY")
            return None
        if rule.action is Transform.TOKENIZE:
            handle = self._store_source_reference(reference, lease=lease, data_class=data_class, origin_scope=origin_scope)
            self._audit_event("PROTECT_SOURCE", lease, data_class=data_class, decision="REFERENCE_HANDLE")
            return handle
        raise PolicyDenied("Unsupported source transformation")

    def _protect_field(self, value: Any, data_class: DataClass, lease_id: str) -> Any:
        lease = self._active_lease(lease_id)
        rule = self.policy.for_class(data_class, lease.purpose)
        quality = rule.quality
        if value is None:
            return self._apply_quality_action(
                action=quality.on_null, value=None, lease=lease, data_class=data_class, reason="NULL"
            )
        if isinstance(value, str) and value.strip() == "":
            return self._apply_quality_action(
                action=quality.on_empty, value=value, lease=lease, data_class=data_class, reason="EMPTY"
            )
        if isinstance(value, bytes):
            # Bytes are privacy-protected without assuming an encoding. This preserves
            # invalid UTF-8 and foreign/legacy payloads byte-for-byte.
            return self._protect_without_validation(value, data_class, lease)
        text = str(value)
        if not is_valid(text, data_class, quality):
            return self._apply_quality_action(
                action=quality.on_invalid, value=value, lease=lease, data_class=data_class, reason="INVALID"
            )
        try:
            return self._protect_without_validation(value, data_class, lease)
        except (ValueError, TypeError, CryptoError):
            return self._apply_quality_action(
                action=quality.on_transform_error,
                value=value,
                lease=lease,
                data_class=data_class,
                reason="TRANSFORM_ERROR",
            )

    def protect_record(
        self,
        record: Mapping[str, Any],
        schema: Mapping[str, DataClass | str],
        lease_id: str,
    ) -> dict[str, Any]:
        lease = self._active_lease(lease_id)
        output: dict[str, Any] = {}
        for field, value in record.items():
            declared = schema.get(field)
            if declared is None:
                action = self.policy.unknown_field_action
                if action is QualityAction.PROTECT:
                    protected = self._protect_field(value, DataClass.UNKNOWN, lease_id)
                    if protected is not _SUPPRESSED:
                        output[field] = protected
                    self._audit_event("FIELD", lease, data_class=DataClass.UNKNOWN, decision="PROTECT_UNCLASSIFIED")
                    continue
                if action is QualityAction.KEEP_VALUE and not self.policy.strict_structured_data:
                    output[field] = value
                    self._audit_event("FIELD", lease, decision="ALLOW_UNCLASSIFIED")
                    continue
                self._audit_event("FIELD", lease, decision="SUPPRESS_UNCLASSIFIED")
                continue
            try:
                data_class = declared if isinstance(declared, DataClass) else DataClass(declared)
            except ValueError as exc:
                raise PolicyDenied("Unknown data class in schema") from exc
            try:
                protected = self._protect_field(value, data_class, lease_id)
            except DataQualityError:
                self._audit_event("FIELD", lease, data_class=data_class, decision="SUPPRESS_QUALITY_ERROR")
                continue
            if protected is not _SUPPRESSED:
                output[field] = protected
        return output

    def protect_reference_record(
        self,
        record: Mapping[str, SourceReference],
        schema: Mapping[str, DataClass | str],
        lease_id: str,
        *,
        origin_scope: str | None = None,
    ) -> dict[str, Any]:
        lease = self._active_lease(lease_id)
        output: dict[str, Any] = {}
        for field, reference in record.items():
            declared = schema.get(field)
            data_class = DataClass.UNKNOWN if declared is None else (declared if isinstance(declared, DataClass) else DataClass(declared))
            protected = self.protect_source_reference(reference, data_class, lease_id, origin_scope=origin_scope)
            if protected is not None:
                output[field] = protected
            if declared is None:
                self._audit_event("FIELD", lease, data_class=DataClass.UNKNOWN, decision="PROTECT_UNCLASSIFIED_REFERENCE")
        return output

    def protect_batch(
        self,
        records: Sequence[Any],
        schema: Mapping[str, DataClass | str],
        lease_id: str,
    ) -> dict[str, Any]:
        lease = self._active_lease(lease_id)
        protected_records: list[dict[str, Any]] = []
        quarantined_indexes: list[int] = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                quarantined_indexes.append(index)
                self._audit_event("RECORD", lease, decision="QUARANTINE_STRUCTURE")
                continue
            protected_records.append(self.protect_record(record, schema, lease_id))
        return {
            "records": protected_records,
            "input_count": len(records),
            "output_count": len(protected_records),
            "quarantined_count": len(quarantined_indexes),
            "quarantined_indexes": quarantined_indexes,
        }

    def protect_text(self, text: str, lease_id: str, *, language: str = "en") -> str:
        """Blocking ingress protection. Async enrichment may only see this protected view."""
        lease = self._active_lease(lease_id)
        try:
            findings: list[Finding] = self.detector.analyze(text, language=language)
        except TypeError:
            findings = self.detector.analyze(text)
        if not findings:
            self._audit_event("TEXT_SCAN", lease, decision="NO_FINDINGS", count=0)
            return text
        chosen: list[Finding] = []
        cursor = -1
        for finding in findings:
            if finding.start < cursor:
                continue
            chosen.append(finding)
            cursor = finding.end
        parts: list[str] = []
        cursor = 0
        for finding in chosen:
            parts.append(text[cursor : finding.start])
            raw = text[finding.start : finding.end]
            protected = self.protect_value(raw, finding.data_class, lease_id)
            parts.append(str(protected) if protected is not None else f"[BBM:{finding.data_class.value}:REMOVED]")
            cursor = finding.end
        parts.append(text[cursor:])
        self._audit_event("TEXT_SCAN", lease, decision="PROTECTED", count=len(chosen))
        return "".join(parts)

    def create_capability(
        self,
        secret: str | bytes,
        lease_id: str,
        *,
        target: str,
        operation: str,
        kind: str = "SECRET",
    ) -> str:
        lease = self._active_lease(lease_id)
        if not self._operation_allowed(lease, target, operation):
            raise CapabilityDenied("Capability operation denied")
        handle = self._store_capsule(
            secret,
            lease=lease,
            data_class=DataClass.SECRET,
            kind=ReferenceKind.CAPABILITY,
            target=target,
            operation=operation,
        )
        self._audit_event(
            "CAPABILITY_CREATE",
            lease,
            decision="ALLOW",
            metadata={"kind": kind, "target": target, "operation": operation},
        )
        return handle

    def _entry_for_handle(self, handle: str, lease: Lease) -> HandleEntry:
        entry = self._load_entry(handle)
        if entry is None or entry.lease_id != lease.lease_id:
            raise RehydrationError()
        return entry

    def validate_handle_for_call(
        self,
        reference: str,
        lease_id: str,
        *,
        expected_class: DataClass | None,
        target: str,
        operation: str,
        capability: bool = False,
    ) -> HandleEntry:
        lease = self._active_lease(lease_id)
        if capability:
            if not CAPABILITY_RE.fullmatch(reference):
                raise RehydrationError()
        else:
            if not HANDLE_RE.fullmatch(reference):
                raise RehydrationError()
            try:
                parsed = parse_handle(reference)
            except CryptoError as exc:
                raise RehydrationError() from exc
            if expected_class is not None and parsed is not expected_class:
                raise PolicyDenied(code=ErrorCode.HANDLE_CLASS_MISMATCH)
        entry = self._entry_for_handle(reference, lease)
        if capability and entry.kind is not ReferenceKind.CAPABILITY:
            raise CapabilityDenied()
        if not capability and entry.kind is ReferenceKind.CAPABILITY:
            raise RehydrationError()
        if expected_class is not None and entry.data_class is not expected_class:
            raise PolicyDenied(code=ErrorCode.HANDLE_CLASS_MISMATCH)
        if not self._operation_allowed(lease, target, operation):
            raise PolicyDenied(code=ErrorCode.OPERATION_DENIED)
        if entry.kind is ReferenceKind.CAPABILITY:
            if entry.target != target or entry.operation != operation:
                raise CapabilityDenied()
        else:
            rule = self.policy.for_class(entry.data_class, lease.purpose)
            allowed = rule.rehydrate.get(target, frozenset())
            if operation not in allowed and "*" not in allowed:
                raise PolicyDenied(code=ErrorCode.TARGET_DENIED)
        if not self.policy.flow_allowed(
            origin_scope=entry.origin_scope, purpose=lease.purpose, target=target, operation=operation
        ):
            raise PolicyDenied(code=ErrorCode.TARGET_DENIED)
        return entry

    def mint_resolution_intent(
        self,
        *,
        lease_id: str,
        target: str,
        operation: str,
        handles: tuple[str, ...],
        payload: dict[str, Any],
        ttl_seconds: int = 30,
    ) -> ResolutionIntent:
        lease = self._active_lease(lease_id)
        return self._intent_authority.mint(
            lease=lease,
            target=target,
            operation=operation,
            handles=handles,
            payload=payload,
            policy_version=self.policy.version,
            ttl_seconds=ttl_seconds,
        )

    def materialize_intent_payload(
        self,
        intent: ResolutionIntent,
        *,
        payload: dict[str, Any],
        target: str,
        operation: str,
        reference_fields: Mapping[str, DataClass],
        capability_fields: frozenset[str],
    ) -> dict[str, Any]:
        """Trusted target-side pull resolution. Not exposed as a model/API decode endpoint."""
        lease = self._active_lease(intent.lease_id)
        self._intent_authority.validate(intent, payload=payload, target=target, operation=operation)
        output = dict(payload)
        for field, data_class in reference_fields.items():
            handle = output[field]
            entry = self.validate_handle_for_call(
                handle,
                lease.lease_id,
                expected_class=data_class,
                target=target,
                operation=operation,
            )
            output[field] = self._references.resolve_value(entry.reference_id, lease_id=lease.lease_id, sources=self._sources)
        for field in capability_fields:
            handle = output[field]
            entry = self.validate_handle_for_call(
                handle,
                lease.lease_id,
                expected_class=None,
                target=target,
                operation=operation,
                capability=True,
            )
            output[field] = self._references.resolve_value(entry.reference_id, lease_id=lease.lease_id, sources=self._sources)
        self._intent_authority.consume(intent.intent_id)
        self._audit_event("RESOLUTION", lease, decision="ALLOW", metadata={"target": target, "operation": operation})
        return output

    def export_guarded_call_for_job(self, call: GuardedCall) -> dict[str, Any]:
        """Move references, not a lease, into the trusted async job envelope."""
        lease = self._active_lease(call.lease_id)
        self._intent_authority.validate(call.intent, payload=call.payload, target=call.target, operation=call.operation)
        refs: dict[str, Any] = {}
        for field, data_class in call.reference_fields.items():
            handle = call.payload[field]
            entry = self.validate_handle_for_call(
                handle,
                lease.lease_id,
                expected_class=data_class,
                target=call.target,
                operation=call.operation,
            )
            exported = self._references.materialize_descriptor(entry.reference_id, lease_id=lease.lease_id)
            refs[field] = {
                "kind": exported.kind.value,
                "data_class": exported.data_class.value,
                "origin_scope": entry.origin_scope,
                "payload": exported.payload,
                "target": entry.target,
                "operation": entry.operation,
            }
        for field in call.capability_fields:
            handle = call.payload[field]
            entry = self.validate_handle_for_call(
                handle,
                lease.lease_id,
                expected_class=None,
                target=call.target,
                operation=call.operation,
                capability=True,
            )
            exported = self._references.materialize_descriptor(entry.reference_id, lease_id=lease.lease_id)
            refs[field] = {
                "kind": exported.kind.value,
                "data_class": exported.data_class.value,
                "origin_scope": entry.origin_scope,
                "payload": exported.payload,
                "target": entry.target,
                "operation": entry.operation,
            }
        self._intent_authority.consume(call.intent.intent_id)
        return {
            "tenant_id": lease.tenant_id,
            "agent_id": lease.agent_id,
            "purpose": lease.purpose,
            "scope": lease.scope,
            "target": call.target,
            "operation": call.operation,
            "references": refs,
            "passthrough": {field: call.payload[field] for field in call.passthrough_fields},
        }

    def policy_check_exported(
        self,
        exported: ExportedReference,
        *,
        origin_scope: str,
        tenant_id: str,
        purpose: str,
        target: str,
        operation: str,
        capability_target: str | None = None,
        capability_operation: str | None = None,
    ) -> None:
        if not self.purpose_active(tenant_id, purpose):
            raise PolicyDenied(code=ErrorCode.PURPOSE_REVOKED)
        if exported.kind is ReferenceKind.CAPABILITY:
            if capability_target != target or capability_operation != operation:
                raise CapabilityDenied()
        else:
            rule = self.policy.for_class(exported.data_class, purpose)
            allowed = rule.rehydrate.get(target, frozenset())
            if operation not in allowed and "*" not in allowed:
                raise PolicyDenied(code=ErrorCode.TARGET_DENIED)
        if not self.policy.flow_allowed(origin_scope=origin_scope, purpose=purpose, target=target, operation=operation):
            raise PolicyDenied(code=ErrorCode.TARGET_DENIED)

    def resolve_exported_for_job(
        self,
        exported: ExportedReference,
        *,
        tenant_id: str,
        purpose: str,
        origin_scope: str,
        target: str,
        operation: str,
        capability_target: str | None = None,
        capability_operation: str | None = None,
    ) -> Any:
        self.policy_check_exported(
            exported,
            origin_scope=origin_scope,
            tenant_id=tenant_id,
            purpose=purpose,
            target=target,
            operation=operation,
            capability_target=capability_target,
            capability_operation=capability_operation,
        )
        return resolve_exported(exported, sources=self._sources)

    def destroy_lease(self, lease_id: str) -> None:
        with self._lock:
            lease = self._load_lease(lease_id)
            if lease is None or lease.revoked:
                return
            self._destroy_locked(lease)

    def _destroy_locked(self, lease: Lease) -> None:
        for handle in list(lease.handles):
            self._state.delete(self.HANDLE_KIND, handle)
        for reference_id in list(lease.reference_ids):
            self._references.delete(reference_id)
        lease.handles.clear()
        lease.reference_ids.clear()
        lease.revoked = True
        self._save_lease(lease)
        self._audit_event("LEASE_DESTROYED", lease, decision="DESTROY")

    def audit_events(self) -> list[dict[str, Any]]:
        return self._backend.list_audit()

    def status(self) -> dict[str, Any]:
        active = 0
        now = datetime.now(UTC)
        for lease_id in self._state.list_ids(self.LEASE_KIND):
            lease = self._load_lease(lease_id)
            if lease is not None and not lease.revoked and lease.expires_at > now:
                active += 1
        return {
            "runtime_version": "0.3.0",
            "policy_version": self.policy.version,
            "active_leases": active,
            "active_agent_handles": self._state.count(self.HANDLE_KIND),
            "encrypted_reference_records": self._references.count(),
        }

    def evidence_snapshot(self) -> dict[str, Any]:
        status = self.status()
        return {
            **status,
            "agent_visible_ciphertext": False,
            "public_decode_api": False,
            "source_data_mutation": False,
            "persistent_identity_mapping": False,
            "persistent_state_encrypted": True,
            "audit_key_process_random": False,
            "unknown_field_default": self.policy.unknown_field_action.value,
            "metrics": dict(self._metrics),
        }
