import pytest

from blueberryme.errors import StructureDenied
from blueberryme.models import DataClass
from blueberryme.proxy import StructuredToolGuard, TargetAdapter


def test_authorized_call_carries_handles_not_plaintext(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case_ref = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    call = guard.authorize_tool_call(
        {"case": case_ref, "status": "REVIEW_COMPLETE"},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
        passthrough_fields={"status"},
    )
    assert call.payload == {"case": case_ref, "status": "REVIEW_COMPLETE"}
    assert "UV-2026-004817" not in str(call.payload)


def test_target_resolves_only_declared_reference_field(runtime, lease):
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="SOURCE_SYSTEM")
    case_ref = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    call = guard.authorize_tool_call(
        {"case": case_ref, "status": "REVIEW_COMPLETE"},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
        passthrough_fields={"status"},
    )
    seen = {}
    response = target.execute(
        call,
        lambda args: seen.update(args) or {"status": args["status"]},
        response_schema={"status": DataClass.PUBLIC},
    )
    assert seen == {"case": "UV-2026-004817", "status": "REVIEW_COMPLETE"}
    assert response == {"ok": True, "result": {"status": "REVIEW_COMPLETE"}}


def test_target_adapter_rejects_call_for_other_target(runtime, lease):
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="LETTER_SERVICE")
    case_ref = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    call = guard.authorize_tool_call(
        {"case": case_ref},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    with pytest.raises(StructureDenied):
        target.execute(call, lambda args: {}, response_schema={})


def test_proxy_rejects_reference_embedded_in_free_text(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case_ref = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(StructureDenied):
        guard.authorize_tool_call(
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
        guard.authorize_tool_call(
            {"unexpected": "value"},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={},
            passthrough_fields=set(),
        )
