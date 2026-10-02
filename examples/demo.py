from pathlib import Path

from blueberryme import BlueberryRuntime, DataClass, MemorySourceAdapter, SourceReference, StructuredToolGuard, TargetAdapter
from blueberryme.policy import load_policy

root = Path(__file__).parents[1]
runtime = BlueberryRuntime(load_policy(root / "policies" / "eu-business.yaml"))
runtime.register_source(
    "claims",
    MemorySourceAdapter(
        {"4711": {"name": "李 明", "case": "UV-2026-004817", "diagnosis": "Fraktur rechter Unterarm"}},
        versions={"4711": "42"},
    ),
)
lease = runtime.create_lease(
    agent_id="external-agent",
    purpose="CLAIM_REVIEW",
    scope="CASE:4711",
    allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
)
view = runtime.protect_reference_record(
    {
        "name": SourceReference("claims", "4711", "name", "42"),
        "case": SourceReference("claims", "4711", "case", "42"),
        "diagnosis": SourceReference("claims", "4711", "diagnosis", "42"),
    },
    {"name": DataClass.PERSON, "case": DataClass.CASE_ID, "diagnosis": DataClass.HEALTH_DATA},
    lease,
)
print(view)

guard = StructuredToolGuard(runtime)
call = guard.authorize_tool_call(
    {"case": view["case"]},
    lease_id=lease,
    target="SOURCE_SYSTEM",
    operation="LOOKUP",
    reference_fields={"case": DataClass.CASE_ID},
)
response = TargetAdapter(runtime, target_id="SOURCE_SYSTEM").execute(
    call,
    lambda args: {"case": args["case"]},
    response_schema={"case": DataClass.CASE_ID},
)
print(response)
