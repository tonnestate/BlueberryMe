from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Iterable, Mapping

from .crypto import args_hash, canonical_json, sign_bytes, verify_signature
from .errors import ErrorCode, IntentDenied
from .models import JobIntent, Lease, ResolutionIntent
from .storage import StateBackend


class IntentAuthority:
    """Mints target-bound one-call authority outside the agent."""

    def __init__(self, key: bytes, backend: StateBackend) -> None:
        self._key = key
        self._backend = backend

    @staticmethod
    def _resolution_unsigned(intent: ResolutionIntent) -> bytes:
        return canonical_json(
            {
                "intent_id": intent.intent_id,
                "call_id": intent.call_id,
                "lease_id": intent.lease_id,
                "target": intent.target,
                "operation": intent.operation,
                "purpose": intent.purpose,
                "handles": list(intent.handles),
                "args_hash": intent.args_hash,
                "policy_version": intent.policy_version,
                "expires_at": intent.expires_at,
                "fields_hash": intent.fields_hash,
            }
        )

    @staticmethod
    def fields_hash(reference_fields: Mapping[str, str], capability_fields: Iterable[str]) -> str:
        return args_hash(
            {
                "reference_fields": {str(k): str(v) for k, v in reference_fields.items()},
                "capability_fields": sorted(str(x) for x in capability_fields),
            }
        )

    @staticmethod
    def _job_unsigned(intent: JobIntent) -> bytes:
        return canonical_json(
            {
                "intent_id": intent.intent_id,
                "job_id": intent.job_id,
                "tenant_id": intent.tenant_id,
                "purpose": intent.purpose,
                "target": intent.target,
                "operation": intent.operation,
                "envelope_hash": intent.envelope_hash,
                "policy_version": intent.policy_version,
                "expires_at": intent.expires_at,
            }
        )

    def mint(
        self,
        *,
        lease: Lease,
        target: str,
        operation: str,
        handles: tuple[str, ...],
        payload: dict,
        policy_version: str,
        ttl_seconds: int = 30,
        fields_hash: str = "",
    ) -> ResolutionIntent:
        if ttl_seconds < 1 or ttl_seconds > 300:
            raise ValueError("intent ttl_seconds must be between 1 and 300")
        unsigned = ResolutionIntent(
            intent_id="BBM1-INTENT-" + secrets.token_urlsafe(18),
            call_id="BBM1-CALL-" + secrets.token_urlsafe(18),
            lease_id=lease.lease_id,
            target=target,
            operation=operation,
            purpose=lease.purpose,
            handles=handles,
            args_hash=args_hash(payload),
            policy_version=policy_version,
            expires_at=(datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat(),
            signature="",
            fields_hash=fields_hash,
        )
        return ResolutionIntent(
            **{**unsigned.__dict__, "signature": sign_bytes(self._key, self._resolution_unsigned(unsigned))}
        )

    def validate(
        self,
        intent: ResolutionIntent,
        *,
        payload: dict,
        target: str,
        operation: str,
        fields_hash: str | None = None,
    ) -> None:
        if self._backend.is_consumed(intent.intent_id):
            raise IntentDenied(code=ErrorCode.INTENT_REPLAY)
        if not verify_signature(self._key, self._resolution_unsigned(intent), intent.signature):
            raise IntentDenied(code=ErrorCode.INTENT_INVALID)
        if target != intent.target or operation != intent.operation:
            raise IntentDenied(code=ErrorCode.INTENT_INVALID)
        if args_hash(payload) != intent.args_hash:
            raise IntentDenied(code=ErrorCode.INTENT_INVALID)
        if fields_hash is not None and fields_hash != intent.fields_hash:
            raise IntentDenied(code=ErrorCode.INTENT_INVALID)
        if datetime.now(UTC) >= datetime.fromisoformat(intent.expires_at):
            raise IntentDenied(code=ErrorCode.INTENT_EXPIRED)

    def mint_job(
        self,
        *,
        job_id: str,
        tenant_id: str,
        purpose: str,
        target: str,
        operation: str,
        envelope_hash: str,
        policy_version: str,
        deadline_seconds: int,
    ) -> JobIntent:
        if deadline_seconds < 1 or deadline_seconds > 86_400:
            raise ValueError("job deadline must be between 1 and 86400 seconds")
        unsigned = JobIntent(
            intent_id="BBM1-JINT-" + secrets.token_urlsafe(18),
            job_id=job_id,
            tenant_id=tenant_id,
            purpose=purpose,
            target=target,
            operation=operation,
            envelope_hash=envelope_hash,
            policy_version=policy_version,
            expires_at=(datetime.now(UTC) + timedelta(seconds=deadline_seconds)).isoformat(),
            signature="",
        )
        return JobIntent(**{**unsigned.__dict__, "signature": sign_bytes(self._key, self._job_unsigned(unsigned))})

    def validate_job(self, intent: JobIntent, *, envelope_hash: str, target: str, operation: str) -> None:
        if self._backend.is_consumed(intent.intent_id):
            raise IntentDenied(code=ErrorCode.INTENT_REPLAY)
        if not verify_signature(self._key, self._job_unsigned(intent), intent.signature):
            raise IntentDenied(code=ErrorCode.INTENT_INVALID)
        if intent.target != target or intent.operation != operation or intent.envelope_hash != envelope_hash:
            raise IntentDenied(code=ErrorCode.INTENT_INVALID)
        if datetime.now(UTC) >= datetime.fromisoformat(intent.expires_at):
            raise IntentDenied(code=ErrorCode.INTENT_EXPIRED)

    def consume(self, intent_id: str) -> None:
        self._backend.consume_once(intent_id)

    def consume_once(self, token_id: str) -> bool:
        return self._backend.consume_once(token_id)

    def consume_or_reject(self, intent_id: str) -> None:
        """Atomically burn a one-time intent. Exactly one concurrent caller wins.

        ``validate`` alone is a check; this is the commit point. Callers MUST call
        this before resolving any value, so two racing requests with the same intent
        can never both reach the target.
        """
        if not self._backend.consume_once(intent_id):
            raise IntentDenied(code=ErrorCode.INTENT_REPLAY)
