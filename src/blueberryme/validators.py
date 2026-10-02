from __future__ import annotations

import re
from datetime import date, datetime

from .models import DataClass, QualityPolicy

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.UNICODE)
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
_PHONE = re.compile(r"^\+?[0-9][0-9 .()\-/]{4,30}$")


def parse_birth_date(value: str, quality: QualityPolicy) -> date | None:
    text = value.strip()
    for fmt in quality.accepted_birth_date_formats:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def is_valid(value: str, data_class: DataClass, quality: QualityPolicy) -> bool:
    if data_class is DataClass.EMAIL:
        return bool(_EMAIL.fullmatch(value.strip()))
    if data_class is DataClass.IBAN:
        compact = re.sub(r"\s+", "", value).upper()
        return bool(_IBAN.fullmatch(compact))
    if data_class is DataClass.PHONE:
        return bool(_PHONE.fullmatch(value.strip()))
    if data_class is DataClass.BIRTH_DATE:
        parsed = parse_birth_date(value, quality)
        return parsed is not None and parsed <= date.today()
    # Names, addresses, case identifiers, free-form health data and public data
    # are intentionally Unicode/locale agnostic in the core. Their syntax belongs
    # in organization-specific policy, not in a Western-centric validator.
    return True
