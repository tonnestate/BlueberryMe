from __future__ import annotations

import re
from dataclasses import dataclass

from .models import DataClass


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    data_class: DataClass
    score: float


class RegexDetector:
    """Small deterministic fallback detector. It is intentionally incomplete."""

    _patterns = [
        (DataClass.EMAIL, re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
        (DataClass.IBAN, re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.I)),
        (DataClass.PHONE, re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{2,5}\)?[ ./-]?)?\d(?:[ .-]?\d){5,12}(?!\w)")),
        (DataClass.SECRET, re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b")),
    ]

    # PHONE false-positive filter. A PHONE match is dropped only if it is
    #  - a thousands/SI-grouped number: 1-3 digits, then groups of exactly 3
    #    digits, each joined by one space or dot ("299 792 458", "1.000.000"), or
    #  - an ISO date YYYY-MM-DD ("2025-02-02").
    # The grouping rule never applies to matches starting with "0" (trunk/
    # international prefix) or containing "+", "(", ")", "/" or "-"; those stay
    # PHONE. When in doubt we keep detection: leaking a phone number is worse
    # than tokenizing a number.
    _not_phone = re.compile(r"[1-9]\d{0,2}(?:[ .]\d{3})+|[12]\d{3}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])")

    def analyze(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for data_class, pattern in self._patterns:
            for match in pattern.finditer(text):
                if data_class is DataClass.PHONE and self._not_phone.fullmatch(match.group()):
                    continue
                findings.append(Finding(match.start(), match.end(), data_class, 1.0))
        return sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))


class PresidioDetector:
    """Optional adapter. Importing BlueberryMe does not require Presidio."""

    _entity_map = {
        "PERSON": DataClass.PERSON,
        "EMAIL_ADDRESS": DataClass.EMAIL,
        "PHONE_NUMBER": DataClass.PHONE,
        "LOCATION": DataClass.ADDRESS,
        "IBAN_CODE": DataClass.IBAN,
    }

    def __init__(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError as exc:
            raise RuntimeError("Install blueberryme[presidio] to use PresidioDetector") from exc
        self._engine = AnalyzerEngine()

    def analyze(self, text: str, language: str = "en") -> list[Finding]:
        results = self._engine.analyze(text=text, language=language)
        findings: list[Finding] = []
        for result in results:
            data_class = self._entity_map.get(result.entity_type)
            if data_class is not None:
                findings.append(Finding(result.start, result.end, data_class, float(result.score)))
        return sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
