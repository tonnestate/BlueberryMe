from blueberryme.dataplane import DataPlaneMode, compile_schema, plan_data_plane
from blueberryme.models import DataClass
from blueberryme.policy import load_policy


def test_schema_is_compiled_once_with_stable_fingerprint():
    policy = load_policy("policies/eu-business.yaml")
    one = compile_schema(policy, {"name": "PERSON", "case": DataClass.CASE_ID})
    two = compile_schema(policy, {"case": DataClass.CASE_ID, "name": "PERSON"})
    assert one.classes["name"] is DataClass.PERSON
    assert one.fingerprint == two.fingerprint


def test_large_aggregate_prefers_pushdown():
    plan = plan_data_plane(estimated_rows=5_000_000, aggregate_query=True, entity_references_required=False)
    assert plan.mode is DataPlaneMode.PUSH_DOWN_AGGREGATE
    assert plan.emit_row_handles is False


def test_entity_level_reasoning_keeps_batch_path():
    plan = plan_data_plane(estimated_rows=5_000_000, aggregate_query=True, entity_references_required=True)
    assert plan.mode is DataPlaneMode.BATCH_PROTECT
    assert plan.emit_row_handles is True
