from blueberryme.models import DataClass
from blueberryme.proxy import StructuredToolGuard, TargetAdapter


def test_secret_is_capability_not_model_context(runtime, lease):
    secret = "github_pat_DO_NOT_LEAK_12345678901234567890"
    cap = runtime.create_capability(secret, lease, target="GITHUB", operation="WRITE_REPO")
    assert cap.startswith("BBM1C.")
    assert secret not in cap


def test_capability_resolves_only_inside_target_adapter(runtime, lease):
    secret = "github_pat_DO_NOT_LEAK_12345678901234567890"
    cap = runtime.create_capability(secret, lease, target="GITHUB", operation="WRITE_REPO")
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="GITHUB")
    call = guard.authorize_tool_call(
        {"credential": cap, "repo": "example/repo"},
        lease_id=lease,
        target="GITHUB",
        operation="WRITE_REPO",
        reference_fields={},
        capability_fields={"credential"},
        passthrough_fields={"repo"},
    )
    seen = {}
    response = target.execute(
        call,
        lambda args: seen.update(args) or {"ok": "yes"},
        response_schema={"ok": DataClass.PUBLIC},
    )
    assert seen["credential"] == secret
    assert secret not in str(response)
