from pathlib import Path

import pytest

from blueberryme.policy import load_policy
from blueberryme.runtime import BlueberryRuntime


@pytest.fixture()
def runtime() -> BlueberryRuntime:
    policy = load_policy(Path(__file__).parents[1] / "policies" / "eu-business.yaml")
    return BlueberryRuntime(policy)


@pytest.fixture()
def lease(runtime: BlueberryRuntime) -> str:
    return runtime.create_lease(
        agent_id="agent-test",
        purpose="CLAIM_REVIEW",
        scope="CASE-4711",
        ttl_seconds=300,
        allowed_operations={
            "SOURCE_SYSTEM": ["LOOKUP", "UPDATE_CASE"],
            "LETTER_SERVICE": ["DELIVER"],
            "MAIL_DELIVERY": ["DELIVER"],
            "TELEPHONY": ["CALL"],
            "GITHUB": ["WRITE_REPO"],
        },
    )
