from pathlib import Path

from blueberryme.models import DataClass
from blueberryme.policy import load_policy
from blueberryme.runtime import BlueberryRuntime

policy = load_policy(Path(__file__).parents[1] / "policies" / "eu-business.yaml")
bbm = BlueberryRuntime(policy)

lease = bbm.create_lease(
    agent_id="unknown-google-agent",
    purpose="CLAIM_REVIEW",
    scope="CLAIM-4711",
    ttl_seconds=300,
    allowed_rehydrate_targets={"SOURCE_SYSTEM"},
)

row = {
    "person": "Max Mustermann",
    "case_id": "UV-2026-004817",
    "diagnosis": "Fraktur rechter Unterarm",
    "iban": "DE02120300000000202051",
}

schema = {
    "person": DataClass.PERSON,
    "case_id": DataClass.CASE_ID,
    "diagnosis": DataClass.HEALTH_DATA,
    "iban": DataClass.IBAN,
}

model_view = bbm.protect_record(row, schema, lease)
print(model_view)

real_case = bbm.rehydrate(model_view["case_id"], lease, target="SOURCE_SYSTEM")
print(real_case)

bbm.destroy_lease(lease)
