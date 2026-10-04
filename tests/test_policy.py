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


import pytest  # noqa: E402


@pytest.mark.parametrize(
    "body",
    [
        "classes:\n  IBAN:\n    action: ALLOW\n",
        "classes:\n  SECRET:\n    action: ALLOW\n",
        "default_action: ALLOW\nclasses:\n  IBAN:\n    action: TOKENIZE\n",  # SECRET falls back to ALLOW
    ],
)
def test_policy_cannot_allow_secret_or_iban_plaintext(tmp_path, body):
    path = tmp_path / "p.yaml"
    path.write_text("version: test\n" + body, encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(path)


def test_default_allow_is_fine_when_protected_classes_are_explicit(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text(
        "version: test\ndefault_action: ALLOW\nclasses:\n  IBAN:\n    action: TOKENIZE\n  SECRET:\n    action: DENY\n",
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.for_class(DataClass.SECRET, "ANY").action is Transform.DENY
