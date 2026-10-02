from blueberryme.models import DataClass


def schema():
    return {
        "name": DataClass.PERSON,
        "birth_date": DataClass.BIRTH_DATE,
        "email": DataClass.EMAIL,
        "phone": DataClass.PHONE,
        "case": DataClass.CASE_ID,
        "diagnosis": DataClass.HEALTH_DATA,
        "iban": DataClass.IBAN,
    }


def test_null_is_normal_data_state(runtime, lease):
    protected = runtime.protect_record({"name": None, "diagnosis": None}, schema(), lease)
    assert protected == {"name": None, "diagnosis": None}


def test_empty_value_does_not_abort_record(runtime, lease):
    protected = runtime.protect_record({"email": "", "diagnosis": "Fraktur"}, schema(), lease)
    assert protected["email"] == ""
    assert protected["diagnosis"] == "Fraktur"


def test_invalid_email_is_suppressed_not_fatal(runtime, lease):
    protected = runtime.protect_record(
        {"email": "not-an-email", "diagnosis": "Fraktur"}, schema(), lease
    )
    assert "email" not in protected
    assert protected["diagnosis"] == "Fraktur"


def test_invalid_birth_date_is_suppressed(runtime, lease):
    protected = runtime.protect_record(
        {"birth_date": "31/31/1977", "diagnosis": "Fraktur"}, schema(), lease
    )
    assert "birth_date" not in protected
    assert protected["diagnosis"] == "Fraktur"


def test_eu_birth_date_format_is_generalized(runtime, lease):
    protected = runtime.protect_record({"birth_date": "14.06.1977"}, schema(), lease)
    assert protected["birth_date"].startswith("AGE_")


def test_unicode_person_is_tokenized(runtime, lease):
    protected = runtime.protect_record({"name": "李 明"}, schema(), lease)
    assert protected["name"].startswith("BBM1H.PERSON.")


def test_non_latin_address_is_tokenized(runtime, lease):
    protected = runtime.protect_record(
        {"address": "東京都千代田区千代田1-1"}, {"address": DataClass.ADDRESS}, lease
    )
    assert protected["address"].startswith("BBM1H.ADDRESS.")


def test_unknown_field_is_safely_suppressed(runtime, lease):
    protected = runtime.protect_record(
        {"diagnosis": "Fraktur", "new_legacy_column": "must-not-pass"}, schema(), lease
    )
    assert protected == {"diagnosis": "Fraktur"}


def test_batch_quarantines_bad_structure_without_stopping(runtime, lease):
    result = runtime.protect_batch(
        [
            {"name": "Max Mustermann", "email": "broken"},
            None,
            {"name": "山田 太郎", "diagnosis": "Fraktur"},
        ],
        schema(),
        lease,
    )
    assert result["input_count"] == 3
    assert result["output_count"] == 2
    assert result["quarantined_count"] == 1
    assert result["quarantined_indexes"] == [1]
    assert len(result["records"]) == 2
