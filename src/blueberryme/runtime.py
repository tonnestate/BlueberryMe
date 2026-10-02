from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from typing import Any, Mapping, Sequence

from .crypto import HANDLE_RE, TOKEN_RE, TokenError, parse_handle, rehydrate as decrypt_token, short_handle, tokenize
from .detectors import Finding, RegexDetector
from .errors import (
    BlueberryError,
    CapabilityDenied,
    DataQualityError,
    ErrorCode,
    LeaseDenied,
    PolicyDenied,
)
from .models import AuditEvent, DataClass, Lease, QualityAction, TokenMode, Transform
from .policy import Policy
from .validators import is_valid, parse_birth_date


_SUPPRESSED = object()


class BlueberryRuntime:
    def __init__(self, policy: Policy, detector: Any | None = None) -> None:
        self.policy = policy
        self.detector = detector or RegexDetector()
        self._leases: dict[str, Lease] = {}
        # Short handles map only to authenticated ciphertext, never plaintext.
        self._handles: dict[str, tuple[str, DataClass, str]] = {}
        # Capabilities store only encrypted secret tokens, never plaintext secrets.
        self._capabilities: dict[str, tuple[str, str, str, str]] = {}
        self._audit: list[AuditEvent] = []
        self._metrics: Counter[str] = Counter()
        self._audit_key = secrets.token_bytes(32)
        self._lock = threading.RLock()

    def _ref(self, value: str) -> str:
        return hmac.new(self._audit_key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

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
        forbidden = {"value", "raw", "plaintext", "ciphertext", "token", "secret", "resolved", "payload"}
        if forbidden.intersection(k.lower() for k in safe_metadata):
            raise BlueberryError("Sensitive audit metadata key rejected")
        self._audit.append(
            AuditEvent(
                timestamp=datetime.now(UTC).isoformat(),
                event_type=event_type,
                lease_ref=self._ref(lease.lease_id),
                agent_ref=self._ref(lease.agent_id),
                purpose=lease.purpose,
                scope_ref=self._ref(lease.scope),
                data_class=data_class.value if data_class else None,
                decision=decision,
                count=count,
                metadata=safe_metadata,
            )
        )
        self._metrics[f"{event_type}:{decision or 'NONE'}"] += count

    @staticmethod
    def _normalise_operations(allowed_operations: Mapping[str, Sequence[str]] | None) -> dict[str, frozenset[str]]:
        return {
            str(target): frozenset(str(op) for op in operations)
            for target, operations in (allowed_operations or {}).items()
        }

    def create_lease(
        self,
        *,
        agent_id: str,
        purpose: str,
        scope: str,
        ttl_seconds: int = 300,
        allowed_operations: Mapping[str, Sequence[str]] | None = None,
        allowed_rehydrate_targets: set[str] | None = None,
    ) -> str:
        if not agent_id or not purpose or not scope:
            raise ValueError("agent_id, purpose and scope are required")
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise ValueError("ttl_seconds must be between 1 and 86400")
        operations = self._normalise_operations(allowed_operations)
        # Compatibility only. Explicit operations are preferred in v0.2.
        for target in allowed_rehydrate_targets or set():
            operations.setdefault(target, frozenset({"*"}))
        lease_id = "BBM1-LEASE-" + secrets.token_urlsafe(18)
        lease = Lease(
            lease_id=lease_id,
            agent_id=agent_id,
            purpose=purpose,
            scope=scope,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            key=bytearray(secrets.token_bytes(64)),
            allowed_operations=operations,
        )
        with self._lock:
            self._leases[lease_id] = lease
            self._audit_event("LEASE_CREATED", lease, decision="ALLOW")
        return lease_id

    def _active_lease(self, lease_id: str) -> Lease:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise LeaseDenied("Unknown lease", code=ErrorCode.LEASE_UNKNOWN)
            if lease.revoked:
                raise LeaseDenied("Lease revoked", code=ErrorCode.LEASE_REVOKED)
            if datetime.now(UTC) >= lease.expires_at:
                self._destroy_locked(lease)
                raise LeaseDenied("Lease expired", code=ErrorCode.LEASE_EXPIRED)
            return lease

    @staticmethod
    def _operation_allowed(lease: Lease, target: str, operation: str) -> bool:
        allowed = lease.allowed_operations.get(target, frozenset())
        return operation in allowed or "*" in allowed

    def _apply_quality_action(
        self,
        *,
        action: QualityAction,
        value: Any,
        lease: Lease,
        data_class: DataClass,
        reason: str,
    ) -> Any:
        if action is QualityAction.KEEP_NULL:
            self._audit_event("DATA_QUALITY", lease, data_class=data_class, decision=f"{reason}_KEEP_NULL")
            return None
        if action is QualityAction.KEEP_EMPTY:
            self._audit_event("DATA_QUALITY", lease, data_class=data_class, decision=f"{reason}_KEEP_EMPTY")
            return ""
        if action is QualityAction.KEEP_VALUE:
            self._audit_event("DATA_QUALITY", lease, data_class=data_class, decision=f"{reason}_KEEP_VALUE")
            return value
        if action is QualityAction.SUPPRESS:
            self._audit_event("DATA_QUALITY", lease, data_class=data_class, decision=f"{reason}_SUPPRESS")
            return _SUPPRESSED
        self._audit_event("DATA_QUALITY", lease, data_class=data_class, decision=f"{reason}_ERROR")
        raise DataQualityError(f"Data quality policy rejected {data_class.value}")

    def _store_short_handle(self, crypto_token: str, data_class: DataClass, lease: Lease) -> str:
        handle = short_handle(crypto_token, data_class, lease)
        with self._lock:
            existing = self._handles.get(handle)
            if existing is not None and existing != (lease.lease_id, data_class, crypto_token):
                raise BlueberryError("Short-handle collision")
            self._handles[handle] = (lease.lease_id, data_class, crypto_token)
            lease.handles.add(handle)
        return handle

    def protect_value(self, value: str, data_class: DataClass, lease_id: str) -> str | None:
        lease = self._active_lease(lease_id)
        rule = self.policy.for_class(data_class, lease.purpose)
        if rule.action is Transform.ALLOW:
            self._audit_event("PROTECT", lease, data_class=data_class, decision="ALLOW")
            return value
        if rule.action is Transform.DENY:
            self._audit_event("PROTECT", lease, data_class=data_class, decision="DENY")
            return None
        if rule.action is Transform.GENERALIZE:
            generalized = self._generalize(value, data_class, rule.quality)
            self._audit_event("PROTECT", lease, data_class=data_class, decision="GENERALIZE")
            return generalized
        if rule.action is Transform.TOKENIZE:
            crypto_token = tokenize(value, data_class, lease)
            if rule.token_mode is TokenMode.CRYPTO_TOKEN:
                protected = crypto_token
            else:
                protected = self._store_short_handle(crypto_token, data_class, lease)
            self._audit_event("PROTECT", lease, data_class=data_class, decision=rule.token_mode.value)
            return protected
        raise PolicyDenied("Unsupported transformation")

    def _protect_field(self, value: Any, data_class: DataClass, lease_id: str) -> Any:
        lease = self._active_lease(lease_id)
        rule = self.policy.for_class(data_class, lease.purpose)
        quality = rule.quality
        if value is None:
            return self._apply_quality_action(
                action=quality.on_null,
                value=None,
                lease=lease,
                data_class=data_class,
                reason="NULL",
            )
        text = str(value)
        if text.strip() == "":
            return self._apply_quality_action(
                action=quality.on_empty,
                value=text,
                lease=lease,
                data_class=data_class,
                reason="EMPTY",
            )
        if not is_valid(text, data_class, quality):
            return self._apply_quality_action(
                action=quality.on_invalid,
                value=text,
                lease=lease,
                data_class=data_class,
                reason="INVALID",
            )
        try:
            protected = self.protect_value(text, data_class, lease_id)
        except (ValueError, TypeError, TokenError) as exc:
            result = self._apply_quality_action(
                action=quality.on_transform_error,
                value=text,
                lease=lease,
                data_class=data_class,
                reason="TRANSFORM_ERROR",
            )
            if result is _SUPPRESSED:
                return _SUPPRESSED
            return result
        return _SUPPRESSED if protected is None else protected

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
                if self.policy.strict_structured_data or self.policy.unknown_field_action is QualityAction.SUPPRESS:
                    self._audit_event("FIELD", lease, decision="SUPPRESS_UNCLASSIFIED")
                    continue
                if self.policy.unknown_field_action is QualityAction.KEEP_VALUE:
                    output[field] = value
                    self._audit_event("FIELD", lease, decision="ALLOW_UNCLASSIFIED")
                    continue
                self._audit_event("FIELD", lease, decision="ERROR_UNCLASSIFIED")
                continue
            try:
                data_class = declared if isinstance(declared, DataClass) else DataClass(declared)
            except ValueError as exc:
                # Schema configuration is a privacy-control error, not bad source data.
                raise PolicyDenied(f"Unknown data class configured for field '{field}'") from exc
            try:
                protected = self._protect_field(value, data_class, lease_id)
            except DataQualityError:
                # Structured business data degrades field-wise; one bad value must not
                # bring down an otherwise safe record.
                self._audit_event("FIELD", lease, data_class=data_class, decision="SUPPRESS_QUALITY_ERROR")
                continue
            if protected is not _SUPPRESSED:
                output[field] = protected
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
            parts.append(text[cursor: finding.start])
            raw = text[finding.start: finding.end]
            protected = self.protect_value(raw, finding.data_class, lease_id)
            parts.append(protected if protected is not None else f"[BBM:{finding.data_class.value}:REMOVED]")
            cursor = finding.end
        parts.append(text[cursor:])
        self._audit_event("TEXT_SCAN", lease, decision="PROTECTED", count=len(chosen))
        return "".join(parts)

    def _crypto_token_for_reference(self, reference: str, lease: Lease) -> tuple[DataClass, str]:
        if TOKEN_RE.fullmatch(reference):
            data_class, _ = decrypt_token(reference, lease)
            return data_class, reference
        if HANDLE_RE.fullmatch(reference):
            data_class = parse_handle(reference)
            with self._lock:
                item = self._handles.get(reference)
            if item is None:
                raise PolicyDenied("Unknown or expired privacy handle", code=ErrorCode.TOKEN_INVALID)
            handle_lease_id, stored_class, crypto_token = item
            if handle_lease_id != lease.lease_id or stored_class is not data_class:
                raise PolicyDenied("Privacy handle is outside this lease", code=ErrorCode.TOKEN_INVALID)
            return data_class, crypto_token
        raise PolicyDenied("Reference must be one complete BBM token or handle", code=ErrorCode.TOKEN_INVALID)

    def rehydrate_reference(
        self,
        reference: str,
        lease_id: str,
        *,
        target: str,
        operation: str,
        expected_class: DataClass | str,
    ) -> str:
        lease = self._active_lease(lease_id)
        if target not in lease.allowed_operations:
            self._audit_event("REHYDRATE", lease, decision="DENY_TARGET", metadata={"target": target, "operation": operation})
            raise PolicyDenied("Target is not permitted by the lease", code=ErrorCode.TARGET_DENIED)
        if not self._operation_allowed(lease, target, operation):
            self._audit_event("REHYDRATE", lease, decision="DENY_OPERATION", metadata={"target": target, "operation": operation})
            raise PolicyDenied("Operation is not permitted by the lease", code=ErrorCode.OPERATION_DENIED)
        try:
            data_class, crypto_token = self._crypto_token_for_reference(reference, lease)
            expected = expected_class if isinstance(expected_class, DataClass) else DataClass(expected_class)
            if data_class is not expected:
                raise PolicyDenied("Reference data class does not match the structured field", code=ErrorCode.TOKEN_CLASS_MISMATCH)
            _, plaintext = decrypt_token(crypto_token, lease)
        except TokenError as exc:
            self._audit_event("REHYDRATE", lease, decision="DENY_TOKEN")
            raise PolicyDenied("Invalid or unauthenticated privacy reference", code=ErrorCode.TOKEN_INVALID) from exc
        rule = self.policy.for_class(data_class, lease.purpose)
        allowed_ops = rule.rehydrate.get(target, frozenset())
        if operation not in allowed_ops and "*" not in allowed_ops:
            self._audit_event(
                "REHYDRATE",
                lease,
                data_class=data_class,
                decision="DENY_CLASS_OPERATION",
                metadata={"target": target, "operation": operation},
            )
            raise PolicyDenied("Data class may not be rehydrated for this target operation", code=ErrorCode.POLICY_DENIED)
        self._audit_event(
            "REHYDRATE",
            lease,
            data_class=data_class,
            decision="ALLOW",
            metadata={"target": target, "operation": operation},
        )
        return plaintext

    def create_capability(
        self,
        secret: str,
        lease_id: str,
        *,
        target: str,
        operation: str,
        kind: str = "SECRET",
    ) -> str:
        lease = self._active_lease(lease_id)
        if not self._operation_allowed(lease, target, operation):
            self._audit_event("CAPABILITY_CREATE", lease, decision="DENY_TARGET_OPERATION", metadata={"target": target, "operation": operation})
            raise CapabilityDenied("Capability target/operation is not permitted by the lease")
        encrypted_secret = tokenize(secret, DataClass.SECRET, lease)
        handle = "BBM1-CAP." + secrets.token_urlsafe(24)
        with self._lock:
            self._capabilities[handle] = (lease_id, target, operation, encrypted_secret)
            lease.capabilities.add(handle)
            self._audit_event(
                "CAPABILITY_CREATE",
                lease,
                decision="ALLOW",
                metadata={"kind": kind, "target": target, "operation": operation},
            )
        return handle

    def resolve_capability(self, handle: str, lease_id: str, *, target: str, operation: str) -> str:
        lease = self._active_lease(lease_id)
        with self._lock:
            item = self._capabilities.get(handle)
        if item is None:
            self._audit_event("CAPABILITY_RESOLVE", lease, decision="DENY_UNKNOWN")
            raise CapabilityDenied("Unknown capability")
        cap_lease_id, cap_target, cap_operation, encrypted_secret = item
        if cap_lease_id != lease_id or cap_target != target or cap_operation != operation:
            self._audit_event("CAPABILITY_RESOLVE", lease, decision="DENY_SCOPE")
            raise CapabilityDenied("Capability does not match lease/target/operation")
        _, secret = decrypt_token(encrypted_secret, lease)
        self._audit_event(
            "CAPABILITY_RESOLVE",
            lease,
            decision="ALLOW",
            metadata={"target": target, "operation": operation},
        )
        return secret

    def destroy_lease(self, lease_id: str) -> None:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                return
            self._destroy_locked(lease)

    def _destroy_locked(self, lease: Lease) -> None:
        if lease.revoked:
            return
        self._audit_event("LEASE_DESTROYED", lease, decision="ALLOW")
        for handle in tuple(lease.capabilities):
            self._capabilities.pop(handle, None)
        lease.capabilities.clear()
        for handle in tuple(lease.handles):
            self._handles.pop(handle, None)
        lease.handles.clear()
        for index in range(len(lease.key)):
            lease.key[index] = 0
        lease.revoked = True
        self._leases.pop(lease.lease_id, None)

    def audit_events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._audit)

    def evidence_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "protocol": "BBM/1",
                "runtime_version": "0.2.0",
                "active_leases": len(self._leases),
                "active_privacy_handles": len(self._handles),
                "active_capabilities": len(self._capabilities),
                "persistent_identity_mapping": False,
                "plaintext_capability_store": False,
                "metrics": dict(sorted(self._metrics.items())),
            }

    def status(self) -> dict[str, Any]:
        return self.evidence_snapshot()

    @staticmethod
    def _generalize(value: str, data_class: DataClass, quality) -> str:
        if data_class is DataClass.BIRTH_DATE:
            born = parse_birth_date(value, quality)
            if born is None:
                raise ValueError("Birth date does not match accepted policy formats")
            today = date.today()
            age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
            lower = max(0, (age // 10) * 10)
            return f"AGE_{lower}_{lower + 9}"
        return f"[BBM:{data_class.value}:GENERALIZED]"
