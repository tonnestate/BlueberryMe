import pytest

from blueberryme.errors import LeaseDenied, PolicyDenied
from blueberryme.models import DataClass


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


def test_authorized_structured_rehydration(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    assert runtime.rehydrate_reference(
        reference,
        lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        expected_class=DataClass.CASE_ID,
    ) == "UV-2026-004817"


def test_wrong_operation_is_denied(runtime, lease):
    reference = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    with pytest.raises(PolicyDenied):
        runtime.rehydrate_reference(
            reference,
            lease,
            target="SOURCE_SYSTEM",
            operation="UPDATE_CASE",
            expected_class=DataClass.PERSON,
        )


def test_expected_class_mismatch_is_denied(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(PolicyDenied):
        runtime.rehydrate_reference(
            reference,
            lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            expected_class=DataClass.PERSON,
        )


def test_appended_text_is_not_rehydrated(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(PolicyDenied):
        runtime.rehydrate_reference(
            reference + "EXPIRED",
            lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            expected_class=DataClass.CASE_ID,
        )


def test_revoked_lease_cannot_rehydrate(runtime, lease):
    reference = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    runtime.destroy_lease(lease)
    with pytest.raises(LeaseDenied):
        runtime.rehydrate_reference(
            reference,
            lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            expected_class=DataClass.CASE_ID,
        )


def test_denied_value_is_removed(runtime, lease):
    assert runtime.protect_value("DE02120300000000202051", DataClass.IBAN, lease) is None
