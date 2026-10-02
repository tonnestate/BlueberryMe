import pytest

from blueberryme.errors import CapabilityDenied, LeaseDenied


def test_secret_is_only_exposed_to_exact_target_operation(runtime, lease):
    secret = "github_pat_DO_NOT_PUT_THIS_IN_MODEL_CONTEXT_123456789"
    handle = runtime.create_capability(
        secret,
        lease,
        target="GITHUB",
        operation="WRITE_REPO",
        kind="PAT",
    )
    assert secret not in handle
    assert runtime.resolve_capability(
        handle,
        lease,
        target="GITHUB",
        operation="WRITE_REPO",
    ) == secret
    with pytest.raises(CapabilityDenied):
        runtime.resolve_capability(handle, lease, target="GITHUB", operation="READ_REPO")


def test_capability_store_contains_no_plaintext_secret(runtime, lease):
    secret = "github_pat_EXAMPLE_12345678901234567890"
    runtime.create_capability(secret, lease, target="GITHUB", operation="WRITE_REPO")
    assert secret not in repr(runtime._capabilities)


def test_capability_dies_with_lease(runtime, lease):
    secret = "github_pat_EXAMPLE_12345678901234567890"
    handle = runtime.create_capability(secret, lease, target="GITHUB", operation="WRITE_REPO")
    runtime.destroy_lease(lease)
    with pytest.raises(LeaseDenied):
        runtime.resolve_capability(handle, lease, target="GITHUB", operation="WRITE_REPO")
