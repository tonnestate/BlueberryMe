import pytest

from blueberryme.errors import LeaseDenied, PolicyDenied, StructureDenied
from blueberryme.models import DataClass
from blueberryme.proxy import StructuredToolGuard, TargetAdapter


def test_same_value_is_stable_inside_one_lease(runtime, lease):
    a = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    b = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    assert a == b
    assert a.startswith("BBM1H.PERSON.")
    assert "Max Mustermann" not in a


def test_same_value_is_unlinkable_across_leases(runtime, lease):
    other = runtime.create_lease(
        agent_id="agent-test",
        purpose="CLAIM_REVIEW",
        scope="CASE-4711",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )
    a = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    b = runtime.protect_value("Max Mustermann", DataClass.PERSON, other)
    assert a != b


def test_same_value_in_different_classes_gets_different_handles(runtime, lease):
    a = runtime.protect_value("4711", DataClass.CASE_ID, lease)
    b = runtime.protect_value("4711", DataClass.PERSON, lease)
    assert a != b


def _call(runtime, lease, payload, operation="LOOKUP", refs=None):
    return StructuredToolGuard(runtime).authorize_tool_call(
        payload,
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation=operation,
        reference_fields=refs if refs is not None else {"case": DataClass.CASE_ID},
    )


def test_authorized_structured_resolution(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    seen = {}
    response = TargetAdapter(runtime, target_id="SOURCE_SYSTEM").execute(
        _call(runtime, lease, {"case": reference}),
        lambda args: seen.update(args) or {"status": "FOUND"},
        response_schema={"status": DataClass.PUBLIC},
    )
    assert seen["case"] == "UV-2026-004817"
    assert response == {"ok": True, "result": {"status": "FOUND"}}


def test_wrong_operation_is_denied(runtime, lease):
    reference = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    with pytest.raises(PolicyDenied):
        _call(runtime, lease, {"person": reference}, operation="UPDATE_CASE", refs={"person": DataClass.PERSON})


def test_expected_class_mismatch_is_denied(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(PolicyDenied):
        _call(runtime, lease, {"case": reference}, refs={"case": DataClass.PERSON})


def test_appended_text_is_not_resolved(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(StructureDenied):
        _call(runtime, lease, {"case": reference + "EXPIRED"})


def test_revoked_lease_cannot_resolve(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    runtime.destroy_lease(lease)
    with pytest.raises(LeaseDenied):
        _call(runtime, lease, {"case": reference})


def test_denied_value_is_removed(runtime, lease):
    # SECRET is DENY in the EU business profile: secrets travel as capabilities only.
    assert runtime.protect_value("ghp_abcdefghijklmnopqrstuvwxyz0123", DataClass.SECRET, lease) is None
