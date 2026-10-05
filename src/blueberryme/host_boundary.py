from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
import secrets
from typing import Any, Iterable

from .disclosure import PrivacyReceipt, ReceiptDecision
from .models import DataClass
from .zone import ProbeStatus


class HostSurface(StrEnum):
    STRUCTURED = "STRUCTURED"
    FREE_TEXT = "FREE_TEXT"
    NON_SENSITIVE = "NON_SENSITIVE"


class HostMediation(StrEnum):
    UNMEDIATED = "UNMEDIATED"
    DENY = "DENY"
    BBM_STRUCTURED = "BBM_STRUCTURED"
    BBM_FREE_TEXT_HANDLE = "BBM_FREE_TEXT_HANDLE"
    BBM_FREE_TEXT_SCAN = "BBM_FREE_TEXT_SCAN"


@dataclass(frozen=True)
class HostCapability:
    """One host-provided function visible to an agent.

    Examples include grid readers, clipboard readers, IDE file/search APIs, browser
    extractors and database result helpers. The host integration owns this manifest;
    agent input must not be allowed to change it.
    """

    name: str
    surface: HostSurface
    mediation: HostMediation
    enabled: bool = True
    can_return_sensitive_values: bool = True


@dataclass(frozen=True)
class HostCapabilityCheck:
    capability: str
    status: ProbeStatus
    detail: str


@dataclass(frozen=True)
class FreeTextEgressResult:
    value: str | None
    receipt: PrivacyReceipt
    mode: HostMediation
    detector_bounded: bool

    @property
    def decision(self) -> ReceiptDecision:
        return self.receipt.decision


def evaluate_host_capabilities(capabilities: Iterable[HostCapability]) -> list[HostCapabilityCheck]:
    """Evaluate whether host-provided capabilities can bypass the BBM boundary.

    This is declarative conformance, not UI introspection. If the host cannot enumerate
    a privileged API, BBM cannot prove that path is mediated.
    """

    checks: list[HostCapabilityCheck] = []
    items = list(capabilities)
    if not items:
        # An empty inventory proves nothing. A host without agent-visible functions must
        # declare that explicitly (for example one NON_SENSITIVE capability that cannot
        # return sensitive values) instead of passing by omission.
        checks.append(
            HostCapabilityCheck(
                "host_manifest",
                ProbeStatus.FAIL,
                "no host capabilities declared; an empty manifest cannot attest the host boundary",
            )
        )
        return checks

    for item in items:
        if not item.enabled:
            checks.append(HostCapabilityCheck(item.name, ProbeStatus.SKIP, "capability disabled"))
            continue
        if item.surface is HostSurface.NON_SENSITIVE and item.can_return_sensitive_values:
            # Contradictory declaration: resolve towards the stricter result.
            checks.append(
                HostCapabilityCheck(
                    item.name,
                    ProbeStatus.FAIL,
                    "contradictory declaration: NON_SENSITIVE surface that can return sensitive values",
                )
            )
            continue
        if not item.can_return_sensitive_values:
            checks.append(HostCapabilityCheck(item.name, ProbeStatus.PASS, "not a sensitive-value surface"))
            continue
        if item.mediation is HostMediation.DENY:
            checks.append(HostCapabilityCheck(item.name, ProbeStatus.PASS, "sensitive host capability denied"))
            continue
        if item.surface is HostSurface.STRUCTURED and item.mediation is HostMediation.BBM_STRUCTURED:
            checks.append(HostCapabilityCheck(item.name, ProbeStatus.PASS, "structured result is BBM-mediated before agent ingress"))
            continue
        if item.surface is HostSurface.FREE_TEXT and item.mediation is HostMediation.BBM_FREE_TEXT_HANDLE:
            checks.append(HostCapabilityCheck(item.name, ProbeStatus.PASS, "free text crosses only as an opaque BBM handle"))
            continue
        if item.surface is HostSurface.FREE_TEXT and item.mediation is HostMediation.BBM_FREE_TEXT_SCAN:
            checks.append(
                HostCapabilityCheck(
                    item.name,
                    ProbeStatus.WARN,
                    "free text is detector-mediated; this is bounded assurance, not zero-disclosure proof",
                )
            )
            continue
        checks.append(
            HostCapabilityCheck(
                item.name,
                ProbeStatus.FAIL,
                "sensitive host capability can return data without a compatible BBM mediation path",
            )
        )
    return checks


def host_check_summary(checks: Iterable[HostCapabilityCheck]) -> dict[str, Any]:
    items = list(checks)
    counts = {status.value: sum(1 for item in items if item.status is status) for status in ProbeStatus}
    return {
        "pass": counts[ProbeStatus.FAIL.value] == 0,
        "counts": counts,
        "checks": [
            {"capability": item.capability, "status": item.status.value, "detail": item.detail}
            for item in items
        ],
    }


def _free_text_receipt(
    runtime: Any,
    lease_id: str,
    *,
    capability: str,
    decision: ReceiptDecision,
    reason_code: str,
    released: bool,
    protected: bool,
    detector_bounded: bool,
) -> PrivacyReceipt:
    context = runtime.lease_context(lease_id)
    receipt = PrivacyReceipt(
        receipt_id="BBMR-" + secrets.token_urlsafe(12),
        timestamp=datetime.now(UTC).isoformat(),
        decision=decision,
        reason_code=reason_code,
        path_coverage="DETECTOR_BOUNDED" if detector_bounded else "VERIFIED",
        dataset_id=f"HOST:{capability}",
        dataset_rule=None,
        risk="UNKNOWN",
        surface="FREE_TEXT",
        purpose=str(context["purpose"]),
        operation=capability,
        destination="AGENT",
        rows_observed=1,
        rows_released=1 if released else 0,
        protected_values=1 if protected else 0,
        denied_values=0 if released else 1,
        aggregate_only_values=0,
        masked_values=0,
        raw_values_released=1 if released and not protected else 0,
        raw_sensitive_values_released=1 if detector_bounded and released else 0,
        unknown_fields=1 if detector_bounded else 0,
        data_classes_observed=(DataClass.UNKNOWN.value,),
    )
    runtime.secure_state.put_json("privacy-receipt", receipt.receipt_id, asdict(receipt), owner=lease_id)
    return receipt


def mediate_free_text(
    runtime: Any,
    text: str,
    lease_id: str,
    *,
    mode: HostMediation,
    language: str = "en",
    origin_scope: str = "HOST:FREE_TEXT",
    capability: str = "FREE_TEXT",
) -> FreeTextEgressResult:
    """Small adapter helper for host-provided free-text result surfaces.

    DENY is the high-assurance default.
    HANDLE releases no text semantics.
    SCAN uses the configured detector and therefore remains detector-bounded; any
    surviving text is an explicitly authorized disclosure, not a zero-disclosure claim.

    The trusted host integration chooses the mode. It must never be caller/agent input.
    """

    if mode is HostMediation.DENY:
        receipt = _free_text_receipt(
            runtime,
            lease_id,
            capability=capability,
            decision=ReceiptDecision.BLOCKED,
            reason_code="BBM_FREE_TEXT_DENIED",
            released=False,
            protected=False,
            detector_bounded=False,
        )
        return FreeTextEgressResult(None, receipt, mode, False)

    if mode is HostMediation.BBM_FREE_TEXT_HANDLE:
        handle = runtime.protect_value_as_handle(
            text,
            DataClass.UNKNOWN,
            lease_id,
            origin_scope=origin_scope,
        )
        receipt = _free_text_receipt(
            runtime,
            lease_id,
            capability=capability,
            decision=ReceiptDecision.VERIFIED_PROTECTED,
            reason_code="BBM_FREE_TEXT_HANDLED",
            released=True,
            protected=True,
            detector_bounded=False,
        )
        return FreeTextEgressResult(str(handle), receipt, mode, False)

    if mode is HostMediation.BBM_FREE_TEXT_SCAN:
        protected = runtime.protect_text(text, lease_id, language=language)
        receipt = _free_text_receipt(
            runtime,
            lease_id,
            capability=capability,
            decision=ReceiptDecision.AUTHORIZED_DISCLOSURE,
            reason_code="BBM_FREE_TEXT_SCANNED_DISCLOSURE",
            released=True,
            protected=False,
            detector_bounded=True,
        )
        return FreeTextEgressResult(protected, receipt, mode, True)

    raise ValueError("Free-text egress requires DENY, BBM_FREE_TEXT_HANDLE or BBM_FREE_TEXT_SCAN")
