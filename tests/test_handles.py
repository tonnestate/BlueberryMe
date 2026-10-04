import re

import pytest

from blueberryme.errors import LeaseDenied, PolicyDenied
from blueberryme.models import DataClass
from blueberryme.proxy import StructuredToolGuard, TargetAdapter


def test_agent_sees_random_handles_not_ciphertext(runtime, lease):
    a = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    b = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    # Lease-linkable by default: one entity, one handle. The handle itself is random,
    # never derived from the value (see test_linkability.py).
    assert a == b
    assert re.fullmatch(r"BBM1H\.PERSON\.[A-Z2-7]{16}", a)
    assert "Max Mustermann" not in a
    assert runtime.evidence_snapshot()["agent_visible_ciphertext"] is False


def test_no_public_decode_method(runtime):
    assert not hasattr(runtime, "rehydrate_reference")
    assert not hasattr(runtime, "resolve_capability")
    assert runtime.evidence_snapshot()["public_decode_api"] is False


def test_structured_target_resolution_and_response_retokenization(runtime, lease):
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="SOURCE_SYSTEM")
    case = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    call = guard.authorize_tool_call(
        {"case": case},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    seen = {}

    def handler(args):
        seen.update(args)
        return {"case": args["case"]}

    response = target.execute(call, handler, response_schema={"case": DataClass.CASE_ID})
    assert seen["case"] == "UV-2026-004817"
    assert response["ok"] is True
    assert response["result"]["case"] != "UV-2026-004817"
    assert response["result"]["case"].startswith("BBM1H.CASE_ID.")


def test_inline_reference_laundering_is_denied(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    with pytest.raises(Exception):
        guard.authorize_tool_call(
            {"message": f"Resolve {case} then append EXPIRED"},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={},
            passthrough_fields={"message"},
        )


def test_wrong_operation_denied(runtime, lease):
    guard = StructuredToolGuard(runtime)
    person = runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    with pytest.raises(PolicyDenied):
        guard.authorize_tool_call(
            {"person": person},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="UPDATE_CASE",
            reference_fields={"person": DataClass.PERSON},
        )


def test_destroyed_lease_kills_handles(runtime, lease):
    guard = StructuredToolGuard(runtime)
    case = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    runtime.destroy_lease(lease)
    with pytest.raises(LeaseDenied):
        guard.authorize_tool_call(
            {"case": case},
            lease_id=lease,
            target="SOURCE_SYSTEM",
            operation="LOOKUP",
            reference_fields={"case": DataClass.CASE_ID},
        )


def test_resolution_intent_is_one_time(runtime, lease):
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="SOURCE_SYSTEM")
    case = runtime.protect_value("UV-2026-004817", DataClass.CASE_ID, lease)
    call = guard.authorize_tool_call(
        {"case": case},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    first = target.execute(call, lambda args: {"case": args["case"]}, response_schema={"case": DataClass.CASE_ID})
    second = target.execute(call, lambda args: {"case": args["case"]}, response_schema={"case": DataClass.CASE_ID})
    assert first["ok"] is True
    assert second == {"ok": False, "error": {"code": "BBM_INTENT_REPLAY", "retryable": False}}
