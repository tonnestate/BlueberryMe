from dataclasses import asdict

from blueberryme.disclosure import EgressGate, ReceiptDecision, load_dataset_policies
from blueberryme.models import DataClass
from blueberryme.policy import load_policy
from blueberryme.runtime import BlueberryRuntime


def _runtime_and_gate():
    policy = load_policy("policies/eu-business.yaml")
    runtime = BlueberryRuntime(policy, master_key=b"D" * 32)
    gate = EgressGate(runtime, load_dataset_policies("policies/eu-business.yaml"))
    return runtime, gate


def test_sql_debugging_employee_grid_is_zero_raw_disclosure():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-local",
        purpose="SQL_DEBUGGING",
        scope="SQL:SSMS",
    )
    result = gate.protect_grid(
        [
            {
                "name": "Alice Example",
                "department": "Claims",
                "IBAN": "DE89370400440532013000",
                "Salary": "72000",
            }
        ],
        {
            "name": DataClass.PERSON,
            "department": DataClass.PUBLIC,
            "IBAN": DataClass.IBAN,
            "Salary": DataClass.UNKNOWN,
        },
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
        surface="SSMS:GetGridResults",
    )

    assert result.receipt.decision is ReceiptDecision.VERIFIED_PROTECTED
    assert result.receipt.raw_values_released == 0
    assert result.receipt.raw_sensitive_values_released == 0
    assert result.receipt.aggregate_only_values == 1
    assert result.receipt.denied_values == 1
    assert result.records[0]["name"].startswith("BBM1H.PERSON.")
    assert result.records[0]["department"].startswith("BBM1H.PUBLIC.")
    assert "IBAN" not in result.records[0]
    assert "Salary" not in result.records[0]

    receipt_text = str(asdict(result.receipt))
    assert "Alice Example" not in receipt_text
    assert "DE89370400440532013000" not in receipt_text


def test_payroll_support_can_explicitly_reveal_one_employee():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-payroll",
        purpose="PAYROLL_SUPPORT",
        scope="EMPLOYEE:4711",
    )
    result = gate.protect_grid(
        [{"name": "Alice Example", "IBAN": "DE89370400440532013000", "Salary": "72000"}],
        {"name": DataClass.PERSON, "IBAN": DataClass.IBAN, "Salary": DataClass.UNKNOWN},
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
        surface="SSMS:GetGridResults",
    )

    assert result.receipt.decision is ReceiptDecision.AUTHORIZED_DISCLOSURE
    assert result.receipt.raw_sensitive_values_released == 3
    assert result.records[0]["name"] == "Alice Example"
    assert result.records[0]["IBAN"] == "DE89370400440532013000"
    assert result.records[0]["Salary"] == "72000"


def test_unknown_dataset_is_blocked_not_silently_allowed():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-local",
        purpose="SQL_DEBUGGING",
        scope="SQL:SSMS",
    )
    result = gate.protect_grid(
        [{"value": "secret"}],
        {"value": DataClass.UNKNOWN},
        lease,
        dataset_id="UNREGISTERED.PROD.dbo.UnknownTable",
        operation="GetGridResults",
        destination="LUNA",
    )
    assert result.records == ()
    assert result.receipt.decision is ReceiptDecision.BLOCKED
    assert result.receipt.reason_code == "BBM_DATASET_CLASSIFICATION_REQUIRED"


def test_unverified_path_never_reports_protected():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-local",
        purpose="SQL_DEBUGGING",
        scope="SQL:SSMS",
    )
    result = gate.protect_grid(
        [{"name": "Alice Example"}],
        {"name": DataClass.PERSON},
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
        path_verified=False,
    )
    assert result.records == ()
    assert result.receipt.decision is ReceiptDecision.UNVERIFIED
    assert result.receipt.path_coverage == "UNVERIFIED"


def test_row_limit_blocks_bulk_employee_disclosure():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-payroll",
        purpose="PAYROLL_SUPPORT",
        scope="EMPLOYEE:4711",
    )
    result = gate.protect_grid(
        [{"name": "A"}, {"name": "B"}],
        {"name": DataClass.PERSON},
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
    )
    assert result.records == ()
    assert result.receipt.decision is ReceiptDecision.BLOCKED
    assert result.receipt.reason_code == "BBM_DATASET_ROW_LIMIT"


def test_wrong_scope_blocks_payroll_reveal():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-payroll",
        purpose="PAYROLL_SUPPORT",
        scope="SQL:SSMS",
    )
    result = gate.protect_grid(
        [{"name": "Alice Example"}],
        {"name": DataClass.PERSON},
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
    )
    assert result.records == ()
    assert result.receipt.reason_code == "BBM_DATASET_SCOPE_DENIED"


def test_wildcard_reveal_policy_is_rejected(tmp_path):
    path = tmp_path / "unsafe.yaml"
    path.write_text(
        """
version: BBM/1-draft-0.4
datasets:
  - id: unsafe
    match: "HR.*"
    default_action: DENY
    purposes:
      SQL_DEBUGGING:
        default_action: DENY
        fields:
          "*": REVEAL
""",
        encoding="utf-8",
    )
    import pytest

    with pytest.raises(ValueError):
        load_dataset_policies(path)


def test_sensitive_reveal_requires_concrete_agent(tmp_path):
    path = tmp_path / "unsafe-agent.yaml"
    path.write_text(
        """
version: BBM/1-draft-0.4
datasets:
  - id: hr
    match: "HR.*"
    default_action: DENY
    purposes:
      PAYROLL_SUPPORT:
        agents: ["*"]
        lease_scopes: ["EMPLOYEE:*"]
        max_reveal_rows_per_lease: 1
        classes:
          IBAN: REVEAL
""",
        encoding="utf-8",
    )
    import pytest

    with pytest.raises(ValueError):
        load_dataset_policies(path)


def test_sensitive_reveal_requires_lease_budget(tmp_path):
    path = tmp_path / "unsafe-budget.yaml"
    path.write_text(
        """
version: BBM/1-draft-0.4
datasets:
  - id: hr
    match: "HR.*"
    default_action: DENY
    purposes:
      PAYROLL_SUPPORT:
        agents: ["luna-payroll"]
        lease_scopes: ["EMPLOYEE:*"]
        classes:
          IBAN: REVEAL
""",
        encoding="utf-8",
    )
    import pytest

    with pytest.raises(ValueError):
        load_dataset_policies(path)


def test_reveal_budget_is_per_lease_not_per_call():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-payroll",
        purpose="PAYROLL_SUPPORT",
        scope="EMPLOYEE:4711",
    )
    args = dict(
        schema={"name": DataClass.PERSON},
        lease_id=lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
    )

    first = gate.protect_grid([{"name": "Alice Example"}], **args)
    second = gate.protect_grid([{"name": "Alice Example"}], **args)

    assert first.receipt.decision is ReceiptDecision.AUTHORIZED_DISCLOSURE
    assert second.records == ()
    assert second.receipt.decision is ReceiptDecision.BLOCKED
    assert second.receipt.reason_code == "BBM_REVEAL_BUDGET_EXHAUSTED"


def test_payroll_reveal_rejects_other_agent():
    runtime, gate = _runtime_and_gate()
    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="other-agent",
        purpose="PAYROLL_SUPPORT",
        scope="EMPLOYEE:4711",
    )
    result = gate.protect_grid(
        [{"name": "Alice Example"}],
        {"name": DataClass.PERSON},
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
    )
    assert result.records == ()
    assert result.receipt.reason_code == "BBM_DATASET_AGENT_DENIED"


def test_reveal_budget_survives_runtime_restart(tmp_path):
    policy = load_policy("policies/eu-business.yaml")
    policies = load_dataset_policies("policies/eu-business.yaml")
    db = tmp_path / "state.db"
    key = b"R" * 32

    r1 = BlueberryRuntime(policy, state_path=db, master_key=key)
    lease = r1.create_lease(
        tenant_id="bank",
        agent_id="luna-payroll",
        purpose="PAYROLL_SUPPORT",
        scope="EMPLOYEE:4711",
    )
    first = EgressGate(r1, policies).protect_grid(
        [{"department": "Claims"}],
        {"department": DataClass.PUBLIC},
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
    )
    assert first.receipt.decision is ReceiptDecision.AUTHORIZED_DISCLOSURE

    r2 = BlueberryRuntime(policy, state_path=db, master_key=key)
    second = EgressGate(r2, policies).protect_grid(
        [{"department": "Claims"}],
        {"department": DataClass.PUBLIC},
        lease,
        dataset_id="HR.PROD.dbo.Employee",
        operation="GetGridResults",
        destination="LUNA",
    )
    assert second.records == ()
    assert second.receipt.reason_code == "BBM_REVEAL_BUDGET_EXHAUSTED"


def test_reveal_budget_is_atomic_across_shared_sqlite_runtimes(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    policy = load_policy("policies/eu-business.yaml")
    policies = load_dataset_policies("policies/eu-business.yaml")
    db = tmp_path / "state.db"
    key = b"A" * 32

    creator = BlueberryRuntime(policy, state_path=db, master_key=key)
    lease = creator.create_lease(
        tenant_id="bank",
        agent_id="luna-payroll",
        purpose="PAYROLL_SUPPORT",
        scope="EMPLOYEE:4711",
    )
    gates = [
        EgressGate(BlueberryRuntime(policy, state_path=db, master_key=key), policies)
        for _ in range(4)
    ]

    def reveal(gate):
        return gate.protect_grid(
            [{"department": "Claims"}],
            {"department": DataClass.PUBLIC},
            lease,
            dataset_id="HR.PROD.dbo.Employee",
            operation="GetGridResults",
            destination="LUNA",
        ).receipt.decision

    with ThreadPoolExecutor(max_workers=4) as pool:
        decisions = list(pool.map(reveal, gates))

    assert decisions.count(ReceiptDecision.AUTHORIZED_DISCLOSURE) == 1
    assert decisions.count(ReceiptDecision.BLOCKED) == 3
