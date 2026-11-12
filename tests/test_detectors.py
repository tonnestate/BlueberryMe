import pytest

from blueberryme.detectors import RegexDetector
from blueberryme.models import DataClass


def _phones(text: str) -> list[str]:
    return [text[f.start:f.end] for f in RegexDetector().analyze(text) if f.data_class is DataClass.PHONE]


@pytest.mark.parametrize(
    "text",
    [
        "299 792 458",
        "6 371 km",
        "1 000 000",
        "1.000.000",
        "384,400",
        "83,237,124",
        "2016/679",
        "10**30",
        "2025-02-02",
        "in 2025",
        "RFC 8446",
        "3.8.10",
    ],
)
def test_grouped_numbers_dates_and_versions_are_not_phone(text):
    assert _phones(text) == []


@pytest.mark.parametrize(
    "phone",
    [
        "+49 30 1234567",
        "030 1234567",
        "030/1234567",
        "0151-12345678",
        "+1 (555) 123-4567",
        "(030) 12 34 56 78",
        "+49 151 234 567",
        "555 123 4567",
    ],
)
def test_real_phone_numbers_stay_phone(phone):
    assert _phones(f"Call {phone} today.") == [phone]


def test_scientific_constant_survives_protect_text(runtime, lease):
    raw = "The speed of light is 299 792 458 m/s."
    assert runtime.protect_text(raw, lease) == raw


def test_phone_is_still_tokenized_by_protect_text(runtime, lease):
    protected = runtime.protect_text("Ruf an: +49 30 1234567.", lease)
    assert "1234567" not in protected
    assert "BBM1H.PHONE." in protected


def test_email_iban_secret_unchanged():
    text = "max@example.de DE89 3704 0044 0532 0130 00 ghp_abcdefghijklmnopqrstuvwxyz"
    classes = {f.data_class for f in RegexDetector().analyze(text)}
    assert {DataClass.EMAIL, DataClass.IBAN, DataClass.SECRET} <= classes
