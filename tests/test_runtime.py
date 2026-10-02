import pytest

from blueberryme.errors import ErrorCode, PolicyDenied, StructureDenied
from blueberryme.models import DataClass
from blueberryme.proxy import StructuredToolGuard


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


def test_expected_class_mismatch_is_denied(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(PolicyDenied) as exc:
        guard.authorize_tool_call(
            {"person": case},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={"person": DataClass.PERSON},
        )
    assert exc.value.code is ErrorCode.HANDLE_CLASS_MISMATCH


def test_appended_text_on_handle_is_denied(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(StructureDenied):
        guard.authorize_tool_call(
            {"case": case + "EXPIRED"},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={"case": DataClass.CASE_ID},
        )


def test_handle_from_other_lease_is_denied(runtime, lease):
    guard = StructuredToolGuard(runtime)
    other = runtime.create_lease(
        agent_id="agent-other",
        purpose="CLAIM_REVIEW",
        scope="CASE:9999",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )
    foreign = runtime.protect_value("UV-2026-009999", DataClass.CASE_ID, other)
    with pytest.raises(Exception):
        guard.authorize_tool_call(
            {"case": foreign},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={"case": DataClass.CASE_ID},
        )


def test_denied_value_is_removed(runtime, lease):
    assert runtime.protect_value("sk-live-0000000000000000", DataClass.SECRET, lease) is None


def test_iban_is_tokenized_not_passed_through(runtime, lease):
    handle = runtime.protect_value("DE02120300000000202051", DataClass.IBAN, lease)
    assert handle.startswith("BBM1H.IBAN.")
    assert "DE02120300000000202051" not in handle
