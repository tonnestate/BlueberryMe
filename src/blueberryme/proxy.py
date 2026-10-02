from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping, Sequence

from .crypto import CAPABILITY_RE, HANDLE_RE, REFERENCE_SEARCH_RE
from .errors import BlueberryError, SafeTargetError, StructureDenied
from .models import DataClass, GuardedCall
from .runtime import BlueberryRuntime


class StructuredToolGuard:
    """Transport-neutral privacy enforcement for tool/MCP calls.

    Agent text is never searched and rewritten into plaintext. Only complete handles
    in declared structured fields may be authorized for a target call.
    """

    def __init__(self, runtime: BlueberryRuntime) -> None:
        self.runtime = runtime

    @staticmethod
    def _contains_reference(value: Any) -> bool:
        if isinstance(value, str):
            return bool(REFERENCE_SEARCH_RE.search(value))
        if isinstance(value, Mapping):
            return any(StructuredToolGuard._contains_reference(v) for v in value.values())
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return any(StructuredToolGuard._contains_reference(v) for v in value)
        return False

    def authorize_tool_call(
        self,
        payload: Mapping[str, Any],
        *,
        lease_id: str,
        target: str,
        operation: str,
        reference_fields: Mapping[str, DataClass | str],
        capability_fields: set[str] | None = None,
        passthrough_fields: set[str] | None = None,
        deny_unknown_fields: bool = True,
        intent_ttl_seconds: int = 30,
    ) -> GuardedCall:
        capability_fields = set(capability_fields or set())
        passthrough_fields = set(passthrough_fields or set())
        normalized_refs = {
            field: value if isinstance(value, DataClass) else DataClass(value)
            for field, value in reference_fields.items()
        }

        output: dict[str, Any] = {}
        handles: list[str] = []
        for field, value in payload.items():
            expected = normalized_refs.get(field)
            if expected is not None:
                if not isinstance(value, str) or not HANDLE_RE.fullmatch(value):
                    raise StructureDenied()
                self.runtime.validate_handle_for_call(
                    value,
                    lease_id,
                    expected_class=expected,
                    target=target,
                    operation=operation,
                )
                output[field] = value
                handles.append(value)
                continue

            if field in capability_fields:
                if not isinstance(value, str) or not CAPABILITY_RE.fullmatch(value):
                    raise StructureDenied()
                self.runtime.validate_handle_for_call(
                    value,
                    lease_id,
                    expected_class=None,
                    target=target,
                    operation=operation,
                    capability=True,
                )
                output[field] = value
                handles.append(value)
                continue

            if field in passthrough_fields:
                if self._contains_reference(value):
                    raise StructureDenied()
                output[field] = deepcopy(value)
                continue

            if deny_unknown_fields:
                raise StructureDenied()
            if self._contains_reference(value):
                raise StructureDenied()
            output[field] = deepcopy(value)

        frozen = deepcopy(output)
        intent = self.runtime.mint_resolution_intent(
            lease_id=lease_id,
            target=target,
            operation=operation,
            handles=tuple(handles),
            payload=frozen,
            ttl_seconds=intent_ttl_seconds,
        )
        return GuardedCall(
            lease_id=lease_id,
            target=target,
            operation=operation,
            payload=frozen,
            reference_fields=normalized_refs,
            capability_fields=frozenset(capability_fields),
            passthrough_fields=frozenset(passthrough_fields),
            intent=intent,
        )

    # v0.2 compatibility name. It now authorizes an intent; it does not return plaintext.
    prepare_tool_call = authorize_tool_call


class TargetAdapter:
    """Trusted target-side pull adapter with mandatory response/error protection."""

    def __init__(self, runtime: BlueberryRuntime, *, target_id: str) -> None:
        self.runtime = runtime
        self.target_id = target_id

    @staticmethod
    def _safe_error(code: str, *, retryable: bool = False) -> dict[str, Any]:
        return {"ok": False, "error": {"code": code, "retryable": retryable}}

    def execute(
        self,
        call: GuardedCall,
        handler: Callable[[dict[str, Any]], Any],
        *,
        response_schema: Mapping[str, DataClass | str] | None = None,
    ) -> dict[str, Any]:
        if call.target != self.target_id:
            raise StructureDenied()
        try:
            resolved = self.runtime.materialize_intent_payload(
                call.intent,
                payload=deepcopy(call.payload),
                target=self.target_id,
                operation=call.operation,
                reference_fields=call.reference_fields,
                capability_fields=call.capability_fields,
            )
        except BlueberryError as exc:
            return self._safe_error(exc.code.value, retryable=exc.failure_class.value == "INFRASTRUCTURE")

        try:
            result = handler(resolved)
        except SafeTargetError as exc:
            return self._safe_error(exc.code, retryable=exc.retryable)
        except Exception:
            # No target exception text or local variables cross the boundary.
            return self._safe_error("BBM_TARGET_ERROR", retryable=False)

        if result is None:
            return {"ok": True}
        if not isinstance(result, Mapping):
            return self._safe_error("BBM_TARGET_ERROR", retryable=False)
        if response_schema is None:
            # A model-visible structured result must have an explicit privacy schema.
            return self._safe_error("BBM_RESPONSE_SCHEMA_REQUIRED", retryable=False)
        protected = self.runtime.protect_record(result, response_schema, call.lease_id)
        return {"ok": True, "result": protected}
