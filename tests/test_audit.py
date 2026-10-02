from blueberryme.models import DataClass


def test_audit_contains_no_payload(runtime, lease):
    raw = "max.mustermann@example.de"
    reference = runtime.protect_value(raw, DataClass.EMAIL, lease)
    runtime.rehydrate_reference(
        reference,
        lease,
        target="MAIL_DELIVERY",
        operation="DELIVER",
        expected_class=DataClass.EMAIL,
    )
    serialized = repr(runtime.audit_events())
    assert raw not in serialized
    assert reference not in serialized


def test_evidence_reports_non_persistent_mapping(runtime, lease):
    runtime.protect_record(
        {"name": "Max Mustermann", "email": "bad", "unknown": "x"},
        {"name": DataClass.PERSON, "email": DataClass.EMAIL},
        lease,
    )
    evidence = runtime.evidence_snapshot()
    assert evidence["persistent_identity_mapping"] is False
    assert evidence["plaintext_capability_store"] is False
    assert evidence["runtime_version"] == "0.2.0"
    assert any("INVALID_SUPPRESS" in key for key in evidence["metrics"])
    assert any("SUPPRESS_UNCLASSIFIED" in key for key in evidence["metrics"])
