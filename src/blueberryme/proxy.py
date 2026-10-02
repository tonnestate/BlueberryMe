from __future__ import annotations

from typing import Any, Mapping, Sequence

from .crypto import REFERENCE_SEARCH_RE
from .errors import StructureDenied
from .models import DataClass
from .runtime import BlueberryRuntime


class StructuredToolGuard:
    """Transport-neutral privacy middleware for tool/MCP integrations.

    v0.2 deliberately rehydrates only complete values in explicitly declared
    structured fields. It never performs token substitution inside free-form text.
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

    def prepare_tool_call(
        self,
        payload: Mapping[str, Any],
        *,
        lease_id: str,
        target: str,
        operation: str,
        reference_fields: Mapping[str, DataClass | str],
        passthrough_fields: set[str] | None = None,
        deny_unknown_fields: bool = True,
    ) -> dict[str, Any]:
        passthrough_fields = set(passthrough_fields or set())
        output: dict[str, Any] = {}
        for field, value in payload.items():
            expected = reference_fields.get(field)
            if expected is not None:
                if not isinstance(value, str):
                    raise StructureDenied(f"Reference field '{field}' must contain one BBM reference")
                output[field] = self.runtime.rehydrate_reference(
                    value,
                    lease_id,
                    target=target,
                    operation=operation,
                    expected_class=expected,
                )
                continue
            if field in passthrough_fields:
                if self._contains_reference(value):
                    raise StructureDenied(
                        f"BBM reference found in non-reference field '{field}'; inline rehydration is forbidden"
                    )
                output[field] = value
                continue
            if deny_unknown_fields:
                raise StructureDenied(f"Tool field '{field}' is not declared by the privacy contract")
            if self._contains_reference(value):
                raise StructureDenied("Undeclared field contains a BBM reference")
            output[field] = value
        return output

    def protect_tool_result(
        self,
        result: Mapping[str, Any],
        *,
        lease_id: str,
        schema: Mapping[str, DataClass | str],
    ) -> dict[str, Any]:
        return self.runtime.protect_record(result, schema, lease_id)
