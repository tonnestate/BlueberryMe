from blueberryme.models import DataClass


def schema():
    return {
        "name": DataClass.PERSON,
        "email": DataClass.EMAIL,
        "birth_date": DataClass.BIRTH_DATE,
        "iban": DataClass.IBAN,
        "diagnosis": DataClass.HEALTH_DATA,
    }


def test_null_is_not_a_privacy_failure(runtime, lease):
    protected = runtime.protect_record({"iban": None, "diagnosis": "Fraktur"}, schema(), lease)
    assert protected["iban"] is None
    assert protected["diagnosis"] == "Fraktur"


def test_invalid_sensitive_value_is_protected_not_passed_or_batch_fatal(runtime, lease):
    protected = runtime.protect_record(
        {"email": "definitely-not-an-email", "diagnosis": "Fraktur"}, schema(), lease
    )
    assert protected["email"].startswith("BBM1H.EMAIL.")
    assert "definitely-not-an-email" not in protected["email"]
    assert protected["diagnosis"] == "Fraktur"


def test_unknown_field_becomes_unknown_handle(runtime, lease):
    protected = runtime.protect_record({"legacy_4711": "some weird value"}, {}, lease)
    assert protected["legacy_4711"].startswith("BBM1H.UNKNOWN.")


def test_international_unicode_is_not_rejected(runtime, lease):
    record = {"name": "李 明", "diagnosis": "กระดูกหัก"}
    protected = runtime.protect_record(record, schema(), lease)
    assert protected["name"].startswith("BBM1H.PERSON.")
    assert protected["diagnosis"] == "กระดูกหัก"


def test_invalid_utf8_bytes_are_preserved_behind_handle(runtime, lease):
    raw = b"\xff\xfe\x00ABC"
    handle = runtime.protect_record({"name": raw}, {"name": DataClass.PERSON}, lease)["name"]
    assert handle.startswith("BBM1H.PERSON.")


def test_bad_batch_item_is_quarantined_not_whole_batch(runtime, lease):
    result = runtime.protect_batch(
        [{"name": "A"}, None, {"name": "B"}],
        {"name": DataClass.PERSON},
        lease,
    )
    assert result["input_count"] == 3
    assert result["output_count"] == 2
    assert result["quarantined_count"] == 1
    assert result["quarantined_indexes"] == [1]
