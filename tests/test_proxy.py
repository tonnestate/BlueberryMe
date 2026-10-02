import pytest

from blueberryme.errors import StructureDenied
from blueberryme.models import DataClass
from blueberryme.proxy import StructuredToolGuard


def test_proxy_only_rehydrates_declared_reference_field(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case_ref = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    prepared = guard.prepare_tool_call(
        {"case": case_ref, "status": "REVIEW_COMPLETE"},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
        passthrough_fields={"status"},
    )
    assert prepared == {"case": "UV-2026-004817", "status": "REVIEW_COMPLETE"}


def test_proxy_rejects_reference_embedded_in_free_text(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case_ref = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(StructureDenied):
        guard.prepare_tool_call(
            {"message": f"Use {case_ref} and append EXPIRED"},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={},
            passthrough_fields={"message"},
        )


def test_proxy_rejects_unknown_tool_field(runtime, lease):
    guard = StructuredToolGuard(runtime)
    with pytest.raises(StructureDenied):
        guard.prepare_tool_call(
            {"unexpected": "value"},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={},
            passthrough_fields=set(),
        )
