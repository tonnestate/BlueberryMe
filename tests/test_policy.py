from pathlib import Path

from blueberryme.models import DataClass, QualityAction, TokenMode
from blueberryme.policy import load_policy


def test_policy_inheritance_and_quality_defaults():
    path = Path(__file__).parents[1] / "policies" / "eu-business.yaml"
    policy = load_policy(path)
    assert policy.strict_structured_data is True
    assert policy.unknown_field_action is QualityAction.SUPPRESS
    person = policy.for_class(DataClass.PERSON, "CLAIM_REVIEW")
    assert person.token_mode is TokenMode.LEASE_HANDLE
    assert "%d.%m.%Y" in policy.default_quality.accepted_birth_date_formats
