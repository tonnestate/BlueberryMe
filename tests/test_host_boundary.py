import pytest

from blueberryme.disclosure import ReceiptDecision
from blueberryme.host_boundary import (
    HostCapability,
    HostMediation,
    HostSurface,
    evaluate_host_capabilities,
    host_check_summary,
    mediate_free_text,
)
from blueberryme.zone import ProbeStatus


def test_unmediated_grid_reader_fails_host_boundary():
    checks = evaluate_host_capabilities(
        [
            HostCapability(
                name="GetGridResults",
                surface=HostSurface.STRUCTURED,
                mediation=HostMediation.UNMEDIATED,
            )
        ]
    )
    assert checks[0].status is ProbeStatus.FAIL
    assert host_check_summary(checks)["pass"] is False


def test_structured_grid_reader_passes_only_when_mediated():
    checks = evaluate_host_capabilities(
        [
            HostCapability(
                name="GetGridResults",
                surface=HostSurface.STRUCTURED,
                mediation=HostMediation.BBM_STRUCTURED,
            )
        ]
    )
    assert checks[0].status is ProbeStatus.PASS
    assert host_check_summary(checks)["pass"] is True


def test_free_text_scan_is_explicitly_detector_bounded():
    checks = evaluate_host_capabilities(
        [
            HostCapability(
                name="ReadEditorText",
                surface=HostSurface.FREE_TEXT,
                mediation=HostMediation.BBM_FREE_TEXT_SCAN,
            )
        ]
    )
    assert checks[0].status is ProbeStatus.WARN
    assert host_check_summary(checks)["pass"] is True


def test_free_text_deny_releases_nothing(runtime, lease):
    result = mediate_free_text(runtime, "sensitive narrative", lease, mode=HostMediation.DENY)
    assert result.value is None
    assert result.decision is ReceiptDecision.BLOCKED
    assert result.detector_bounded is False


def test_free_text_handle_releases_no_text_semantics(runtime, lease):
    raw = "sensitive narrative"
    result = mediate_free_text(
        runtime,
        raw,
        lease,
        mode=HostMediation.BBM_FREE_TEXT_HANDLE,
        capability="ReadEditorText",
    )
    assert raw not in result.value
    assert result.value.startswith("BBM1H.UNKNOWN.")
    assert result.decision is ReceiptDecision.VERIFIED_PROTECTED
    assert result.receipt.reason_code == "BBM_FREE_TEXT_HANDLED"
    assert runtime.secure_state.get_json("privacy-receipt", result.receipt.receipt_id) is not None
    assert result.detector_bounded is False


def test_free_text_scan_never_claims_zero_disclosure(runtime, lease):
    raw = "Contact max.mustermann@example.de about the case."
    result = mediate_free_text(
        runtime,
        raw,
        lease,
        mode=HostMediation.BBM_FREE_TEXT_SCAN,
        capability="ReadEditorText",
    )
    assert "max.mustermann@example.de" not in result.value
    assert "BBM1H.EMAIL." in result.value
    assert result.decision is ReceiptDecision.AUTHORIZED_DISCLOSURE
    assert result.receipt.reason_code == "BBM_FREE_TEXT_SCANNED_DISCLOSURE"
    assert result.receipt.path_coverage == "DETECTOR_BOUNDED"
    assert result.receipt.raw_sensitive_values_released == 1
    stored = runtime.secure_state.get_json("privacy-receipt", result.receipt.receipt_id)
    assert stored is not None
    assert "max.mustermann@example.de" not in str(stored)
    assert result.detector_bounded is True


def test_free_text_helper_rejects_incompatible_mode(runtime, lease):
    with pytest.raises(ValueError):
        mediate_free_text(runtime, "text", lease, mode=HostMediation.BBM_STRUCTURED)


def test_empty_host_manifest_fails_closed():
    checks = evaluate_host_capabilities([])
    assert len(checks) == 1
    assert checks[0].capability == "host_manifest"
    assert checks[0].status is ProbeStatus.FAIL
    assert host_check_summary(checks)["pass"] is False


def test_explicit_non_sensitive_declaration_passes():
    checks = evaluate_host_capabilities(
        [
            HostCapability(
                name="NONE",
                surface=HostSurface.NON_SENSITIVE,
                mediation=HostMediation.UNMEDIATED,
                can_return_sensitive_values=False,
            )
        ]
    )
    assert checks[0].status is ProbeStatus.PASS
    assert host_check_summary(checks)["pass"] is True


def test_non_sensitive_surface_that_can_return_sensitive_values_fails():
    checks = evaluate_host_capabilities(
        [
            HostCapability(
                name="GetGridResults",
                surface=HostSurface.NON_SENSITIVE,
                mediation=HostMediation.UNMEDIATED,
                can_return_sensitive_values=True,
            )
        ]
    )
    assert checks[0].status is ProbeStatus.FAIL
    assert "contradictory" in checks[0].detail
    assert host_check_summary(checks)["pass"] is False


def test_non_sensitive_contradiction_is_not_rescued_by_mediation():
    checks = evaluate_host_capabilities(
        [
            HostCapability(
                name="ClipboardReader",
                surface=HostSurface.NON_SENSITIVE,
                mediation=HostMediation.BBM_STRUCTURED,
            )
        ]
    )
    assert checks[0].status is ProbeStatus.FAIL
