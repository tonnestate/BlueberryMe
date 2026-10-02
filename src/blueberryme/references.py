from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .errors import SourceUnavailable, ValueDriftError
from .models import DataClass, ReferenceKind, SourceReference
from .storage import SecureState


@dataclass(frozen=True)
class ExportedReference:
    kind: ReferenceKind
    data_class: DataClass
    payload: dict[str, Any]


class SourceAdapter(Protocol):
    def read(self, reference: SourceReference) -> tuple[Any, str | None]: ...


class MemorySourceAdapter:
    """Read-only source adapter for tests/examples. It never mutates source records."""

    def __init__(self, records: dict[str, dict[str, Any]], versions: dict[str, str] | None = None) -> None:
        self._records = records
        self._versions = versions or {key: "1" for key in records}

    def read(self, reference: SourceReference) -> tuple[Any, str | None]:
        try:
            value = self._records[reference.record_key][reference.field]
            version = self._versions.get(reference.record_key)
        except KeyError as exc:
            raise SourceUnavailable("Source reference could not be read") from exc
        return value, version

    def set_version_for_test(self, record_key: str, version: str) -> None:
        self._versions[record_key] = version


class CallbackSourceAdapter:
    """Small adapter for integrating an existing read function without another framework."""

    def __init__(self, reader: Callable[[SourceReference], tuple[Any, str | None]]) -> None:
        self._reader = reader

    def read(self, reference: SourceReference) -> tuple[Any, str | None]:
        return self._reader(reference)


class SourceRegistry:
    def __init__(self) -> None:
        self._sources: dict[str, SourceAdapter] = {}

    def register(self, source_id: str, adapter: SourceAdapter) -> None:
        if not source_id:
            raise ValueError("source_id is required")
        self._sources[source_id] = adapter

    def read(self, reference: SourceReference, *, enforce_version: bool = True) -> Any:
        adapter = self._sources.get(reference.source_id)
        if adapter is None:
            raise SourceUnavailable("Source adapter is not registered")
        value, current_version = adapter.read(reference)
        if enforce_version and reference.row_version is not None and current_version != reference.row_version:
            raise ValueDriftError("Source value changed after reference creation")
        return value


class ReferenceStore:
    """Encrypted reference store inside the privacy boundary.

    Agent-visible handles never contain ciphertext. This store contains either an
    encrypted source pointer or an encrypted capsule for values that have no source.
    """

    KIND = "reference"

    def __init__(self, state: SecureState) -> None:
        self._state = state

    @staticmethod
    def _encode_capsule(value: Any) -> dict[str, Any]:
        if isinstance(value, bytes):
            return {"encoding": "bytes", "data": base64.b64encode(value).decode("ascii")}
        if isinstance(value, str):
            return {"encoding": "utf8", "data": value}
        return {"encoding": "json", "data": value}

    @staticmethod
    def _decode_capsule(payload: dict[str, Any]) -> Any:
        if payload.get("encoding") == "bytes":
            return base64.b64decode(payload["data"])
        return payload.get("data")

    def put_capsule(
        self,
        reference_id: str,
        value: Any,
        *,
        lease_id: str,
        data_class: DataClass,
        kind: ReferenceKind = ReferenceKind.CAPSULE,
        expires_at: float | None = None,
    ) -> None:
        self._state.put_json(
            self.KIND,
            reference_id,
            {
                "lease_id": lease_id,
                "kind": kind.value,
                "data_class": data_class.value,
                "payload": self._encode_capsule(value),
            },
            expires_at=expires_at,
        )

    def put_source(
        self,
        reference_id: str,
        reference: SourceReference,
        *,
        lease_id: str,
        data_class: DataClass,
        expires_at: float | None = None,
    ) -> None:
        self._state.put_json(
            self.KIND,
            reference_id,
            {
                "lease_id": lease_id,
                "kind": ReferenceKind.SOURCE.value,
                "data_class": data_class.value,
                "payload": {
                    "source_id": reference.source_id,
                    "record_key": reference.record_key,
                    "field": reference.field,
                    "row_version": reference.row_version,
                },
            },
            expires_at=expires_at,
        )

    def materialize_descriptor(self, reference_id: str, *, lease_id: str) -> ExportedReference:
        item = self._state.get_json(self.KIND, reference_id)
        if item is None or item.get("lease_id") != lease_id:
            raise SourceUnavailable("Reference is unavailable")
        return ExportedReference(
            kind=ReferenceKind(item["kind"]),
            data_class=DataClass(item["data_class"]),
            payload=dict(item["payload"]),
        )

    def resolve_value(self, reference_id: str, *, lease_id: str, sources: SourceRegistry) -> Any:
        return resolve_exported(self.materialize_descriptor(reference_id, lease_id=lease_id), sources=sources)

    def delete(self, reference_id: str) -> None:
        self._state.delete(self.KIND, reference_id)

    def count(self) -> int:
        return self._state.count(self.KIND)


def resolve_exported(exported: ExportedReference, *, sources: SourceRegistry) -> Any:
    if exported.kind is ReferenceKind.SOURCE:
        p = exported.payload
        return sources.read(
            SourceReference(
                source_id=str(p["source_id"]),
                record_key=str(p["record_key"]),
                field=str(p["field"]),
                row_version=None if p.get("row_version") is None else str(p["row_version"]),
            ),
            enforce_version=True,
        )
    return ReferenceStore._decode_capsule(exported.payload)
