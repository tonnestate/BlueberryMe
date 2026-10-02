from blueberryme.models import DataClass


def test_audit_contains_no_payload_or_handle(runtime, lease):
    secret = "max.mustermann@example.de"
    handle = runtime.protect_value(secret, DataClass.EMAIL, lease)
    joined = str(runtime.audit_events())
    assert secret not in joined
    assert handle not in joined


def test_evidence_states_boundary_properties(runtime, lease):
    runtime.protect_value("Max Mustermann", DataClass.PERSON, lease)
    e = runtime.evidence_snapshot()
    assert e["agent_visible_ciphertext"] is False
    assert e["public_decode_api"] is False
    assert e["source_data_mutation"] is False
    assert e["persistent_identity_mapping"] is False
    assert e["persistent_state_encrypted"] is True
    assert e["audit_key_process_random"] is False
