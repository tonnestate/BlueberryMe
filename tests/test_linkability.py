"""Lease-local handle stability (entity coherence) and its limits."""
import re
from pathlib import Path

from blueberryme.models import DataClass, SourceReference
from blueberryme.policy import load_policy
from blueberryme.references import MemorySourceAdapter
from blueberryme.runtime import BlueberryRuntime

ROOT = Path(__file__).parents[1] / "policies"


def test_text_mentions_of_one_email_share_a_handle(runtime, lease):
    text = runtime.protect_text("Write to a@b.de. Then cc a@b.de and c@d.de.", lease)
    handles = re.findall(r"BBM1H\.EMAIL\.[A-Z2-7]{16}", text)
    assert len(handles) == 3
    assert handles[0] == handles[1] != handles[2]


def test_record_and_text_paths_agree(runtime, lease):
    record = runtime.protect_record({"email": "a@b.de"}, {"email": DataClass.EMAIL}, lease)
    text = runtime.protect_text("mail a@b.de", lease)
    assert record["email"] in text


def test_same_source_pointer_same_handle_but_different_records_stay_distinct(runtime, lease):
    runtime.register_source(
        "crm",
        MemorySourceAdapter({"1": {"name": "Max"}, "2": {"name": "Max"}}, versions={"1": "1", "2": "1"}),
    )
    a = runtime.protect_source_reference(SourceReference("crm", "1", "name", "1"), DataClass.PERSON, lease)
    b = runtime.protect_source_reference(SourceReference("crm", "1", "name", "1"), DataClass.PERSON, lease)
    c = runtime.protect_source_reference(SourceReference("crm", "2", "name", "1"), DataClass.PERSON, lease)
    assert a == b
    # Two customers called "Max" are two people: the pointer is the identity.
    assert a != c


def test_destroyed_lease_forgets_index(runtime, lease):
    a = runtime.protect_value("Max", DataClass.PERSON, lease)
    runtime.destroy_lease(lease)
    assert runtime.status()["active_agent_handles"] == 0
    assert runtime.status()["encrypted_reference_records"] == 0
    fresh = runtime.create_lease(agent_id="x", purpose="CLAIM_REVIEW", scope="S")
    assert runtime.protect_value("Max", DataClass.PERSON, fresh) != a


def test_repeated_values_do_not_grow_state(runtime, lease):
    schema = {"name": DataClass.PERSON, "email": DataClass.EMAIL}
    records = [{"name": f"P{i % 5}", "email": f"p{i % 5}@x.de"} for i in range(200)]
    runtime.protect_batch(records, schema, lease)
    assert runtime.status()["active_agent_handles"] == 10


def test_occurrence_linkability_is_configurable(tmp_path):
    (tmp_path / "base.yaml").write_text((ROOT / "base.yaml").read_text())
    policy_text = (ROOT / "eu-business.yaml").read_text().replace(
        "  PERSON:\n    action: TOKENIZE\n", "  PERSON:\n    action: TOKENIZE\n    linkability: OCCURRENCE\n"
    )
    (tmp_path / "p.yaml").write_text(policy_text)
    runtime = BlueberryRuntime(load_policy(tmp_path / "p.yaml"), master_key=b"L" * 32)
    lease = runtime.create_lease(agent_id="a", purpose="CLAIM_REVIEW", scope="S")
    assert runtime.protect_value("Max", DataClass.PERSON, lease) != runtime.protect_value("Max", DataClass.PERSON, lease)
    # Other classes keep the default.
    assert runtime.protect_value("a@b.de", DataClass.EMAIL, lease) == runtime.protect_value("a@b.de", DataClass.EMAIL, lease)


def test_audit_is_aggregated_per_call_not_per_value(runtime, lease):
    before = len(runtime.audit_events())
    runtime.protect_batch([{"name": f"P{i}"} for i in range(100)], {"name": DataClass.PERSON}, lease)
    rows = runtime.audit_events()[before:]
    assert len(rows) == 1
    assert rows[0]["count"] == 100
    assert rows[0]["decision"] == "RANDOM_HANDLE"
