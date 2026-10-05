from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable

from .disclosure import ReceiptDecision
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
    decision: ReceiptDecision
    mode: HostMediation
    detector_bounded: bool


def evaluate_host_capabilities(capabilities: Iterable[HostCapability]) -> list[HostCapabilityCheck]:
    """Evaluate whether host-provided capabilities can bypass the BBM boundary.

    This is declarative conformance, not UI introspection. If the host cannot enumerate
    a privileged API, BBM cannot prove that path is mediated.
    """

    checks: list[HostCapabilityCheck] = []
    for item in capabilities:
        if not item.enabled:
            checks.append(HostCapabilityCheck(item.name, ProbeStatus.SKIP, "capability disabled"))
            continue
        if not item.can_return_sensitive_values or item.surface is HostSurface.NON_SENSITIVE:
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


def mediate_free_text(
    runtime: Any,
    text: str,
    lease_id: str,
    *,
    mode: HostMediation,
    language: str = "en",
    origin_scope: str = "HOST:FREE_TEXT",
) -> FreeTextEgressResult:
    """Small adapter helper for host-provided free-text result surfaces.

    DENY is the high-assurance default.
    HANDLE releases no text semantics.
    SCAN uses the configured detector and therefore remains detector-bounded; any
    surviving text is an explicitly authorized disclosure, not a zero-disclosure claim.

    The trusted host integration chooses the mode. It must never be caller/agent input.
    """

    if mode is HostMediation.DENY:
        return FreeTextEgressResult(None, ReceiptDecision.BLOCKED, mode, False)

    if mode is HostMediation.BBM_FREE_TEXT_HANDLE:
        handle = runtime.protect_value_as_handle(
            text,
            DataClass.UNKNOWN,
            lease_id,
            origin_scope=origin_scope,
        )
        return FreeTextEgressResult(str(handle), ReceiptDecision.VERIFIED_PROTECTED, mode, False)

    if mode is HostMediation.BBM_FREE_TEXT_SCAN:
        protected = runtime.protect_text(text, lease_id, language=language)
        return FreeTextEgressResult(
            protected,
            ReceiptDecision.AUTHORIZED_DISCLOSURE,
            mode,
            True,
        )

    raise ValueError("Free-text egress requires DENY, BBM_FREE_TEXT_HANDLE or BBM_FREE_TEXT_SCAN")
