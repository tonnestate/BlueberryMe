from copy import deepcopy

from blueberryme.models import DataClass, SourceReference
from blueberryme.proxy import StructuredToolGuard, TargetAdapter
from blueberryme.references import MemorySourceAdapter


def test_source_is_never_mutated(runtime, lease):
    records = {"4711": {"name": "Max Mustermann", "case": "UV-4711"}}
    before = deepcopy(records)
    runtime.register_source("claims", MemorySourceAdapter(records, versions={"4711": "7"}))
    view = runtime.protect_reference_record(
        {"name": SourceReference("claims", "4711", "name", "7")},
        {"name": DataClass.PERSON},
        lease,
    )
    assert view["name"].startswith("BBM1H.PERSON.")
    assert records == before


def test_value_drift_fails_item_without_exposing_new_value(runtime, lease):
    source = MemorySourceAdapter({"4711": {"case": "UV-OLD"}}, versions={"4711": "1"})
    runtime.register_source("claims", source)
    view = runtime.protect_reference_record(
        {"case": SourceReference("claims", "4711", "case", "1")},
        {"case": DataClass.CASE_ID},
        lease,
    )
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="SOURCE_SYSTEM")
    call = guard.authorize_tool_call(
        {"case": view["case"]},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    source.set_version_for_test("4711", "2")
    response = target.execute(call, lambda args: {"case": args["case"]}, response_schema={"case": DataClass.CASE_ID})
    assert response == {"ok": False, "error": {"code": "BBM_VALUE_DRIFT", "retryable": False}}
