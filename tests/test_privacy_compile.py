from blueberryme.disclosure import EgressGate, ReceiptDecision, load_dataset_policies
from blueberryme.models import DataClass
from blueberryme.policy import load_policy
from blueberryme.privacy_compile import EvidenceProvenance, PrivacyRecipeCompiler, RecipeRole
from blueberryme.runtime import BlueberryRuntime


def _parts(detector=None):
    policy = load_policy("policies/eu-business.yaml")
    runtime = BlueberryRuntime(policy, master_key=b"C" * 32)
    datasets = load_dataset_policies("policies/eu-business.yaml")
    compiler = PrivacyRecipeCompiler(runtime, policy, datasets, detector=detector)
    return policy, runtime, datasets, compiler


def test_compile_once_hits_exact_recipe_on_second_call():
    _, runtime, _, compiler = _parts()
    schema = {"name": DataClass.PERSON, "IBAN": DataClass.IBAN, "Salary": DataClass.UNKNOWN}

    first = compiler.get_or_compile(
        schema,
        dataset_id="HR.PROD.dbo.Employee",
        purpose="SQL_DEBUGGING",
        operation="GetGridResults",
        destination="LUNA",
    )
    second = compiler.get_or_compile(
        schema,
        dataset_id="HR.PROD.dbo.Employee",
        purpose="SQL_DEBUGGING",
        operation="GetGridResults",
        destination="LUNA",
    )

    assert first.cache_hit is False
    assert first.recipe.role is RecipeRole.PRIMARY
    assert first.recipe.reusable is True
    assert second.cache_hit is True
    assert second.stages == ("RECIPE",)
    assert second.recipe.recipe_id == first.recipe.recipe_id
    assert runtime.secure_state.count("privacy-recipe") == 1


def test_independent_evidence_cross_confirms_name():
    _, _, _, compiler = _parts()
    result = compiler.get_or_compile(
        {"name": DataClass.PERSON},
        dataset_id="HR.PROD.dbo.Employee",
        purpose="SQL_DEBUGGING",
        operation="GetGridResults",
        destination="LUNA",
    )
    field = result.recipe.fields[0]
    assert field.data_class is DataClass.PERSON
    assert field.provenance is EvidenceProvenance.CROSS_CONFIRMED


def test_agent_hint_can_only_tighten_and_is_not_promoted():
    _, runtime, _, compiler = _parts()
    result = compiler.get_or_compile(
        {"name": DataClass.PERSON},
        dataset_id="HR.PROD.dbo.Employee",
        purpose="PAYROLL_SUPPORT",
        operation="GetGridResults",
        destination="LUNA",
        agent_hints={"name": DataClass.HEALTH_DATA},
    )
    field = result.recipe.fields[0]
    assert field.action.value == "DENY"
    assert result.recipe.role is RecipeRole.CANDIDATE
    assert result.recipe.reusable is False
    assert runtime.secure_state.count("privacy-recipe") == 0
    assert runtime.secure_state.count("privacy-recipe-candidate") == 1


def test_detector_contradiction_stays_candidate():
    def detector(field, values):
        return DataClass.HEALTH_DATA if field == "name" else None

    _, _, _, compiler = _parts(detector=detector)
    result = compiler.get_or_compile(
        {"name": DataClass.PERSON},
        dataset_id="HR.PROD.dbo.Employee",
        purpose="SQL_DEBUGGING",
        operation="GetGridResults",
        destination="LUNA",
        samples=[{"name": "Alice Example"}],
    )
    assert result.recipe.contradictions == 1
    assert result.recipe.reusable is False
    assert result.recipe.fields[0].action.value == "DENY"


def test_compiled_recipe_enforces_hot_path_without_raw_employee_values():
    _, runtime, datasets, compiler = _parts()
    schema = {"name": DataClass.PERSON, "IBAN": DataClass.IBAN, "Salary": DataClass.UNKNOWN}
    compiled = compiler.get_or_compile(
        schema,
        dataset_id="HR.PROD.dbo.Employee",
        purpose="SQL_DEBUGGING",
        operation="GetGridResults",
        destination="LUNA",
    ).recipe

    lease = runtime.create_lease(
        tenant_id="bank",
        agent_id="luna-local",
        purpose="SQL_DEBUGGING",
        scope="SQL:SSMS",
    )
    result = EgressGate(runtime, datasets).protect_compiled_grid(
        [{"name": "Alice Example", "IBAN": "DE89370400440532013000", "Salary": "72000", "new_field": "x"}],
        lease,
        recipe=compiled,
        surface="SSMS:GetGridResults",
    )

    assert result.receipt.decision is ReceiptDecision.VERIFIED_PROTECTED
    assert result.receipt.raw_sensitive_values_released == 0
    assert result.records[0]["name"].startswith("BBM1H.PERSON.")
    assert "IBAN" not in result.records[0]
    assert "Salary" not in result.records[0]
    assert "new_field" not in result.records[0]
    assert result.receipt.unknown_fields == 1


def test_dispatch_key_changes_with_destination():
    _, _, _, compiler = _parts()
    schema = {"name": DataClass.PERSON}
    a = compiler.get_or_compile(
        schema,
        dataset_id="HR.PROD.dbo.Employee",
        purpose="SQL_DEBUGGING",
        operation="GetGridResults",
        destination="LUNA",
    ).recipe
    b = compiler.get_or_compile(
        schema,
        dataset_id="HR.PROD.dbo.Employee",
        purpose="SQL_DEBUGGING",
        operation="GetGridResults",
        destination="AGENT:OTHER",
    ).recipe
    assert a.dispatch_key != b.dispatch_key
