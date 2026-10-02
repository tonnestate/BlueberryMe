from pathlib import Path

from blueberryme.models import DataClass, QualityAction, Transform
from blueberryme.policy import load_policy


def test_policy_inheritance_and_safe_defaults():
    policy = load_policy(Path(__file__).parents[1] / "policies" / "eu-business.yaml")
    assert policy.unknown_field_action is QualityAction.PROTECT
    assert policy.for_class(DataClass.PERSON, "CLAIM_REVIEW").action is Transform.TOKENIZE
    assert policy.for_class(DataClass.HEALTH_DATA, "CLAIM_REVIEW").action is Transform.ALLOW


def test_flow_policy_is_origin_to_sink():
    policy = load_policy(Path(__file__).parents[1] / "policies" / "eu-business.yaml")
    assert policy.flow_allowed(
        origin_scope="CASE:4711", purpose="CLAIM_REVIEW", target="SOURCE_SYSTEM", operation="LOOKUP"
    )
    assert not policy.flow_allowed(
        origin_scope="CASE:4711", purpose="CLAIM_REVIEW", target="EVIL_SINK", operation="UPLOAD"
    )
