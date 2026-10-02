def test_text_ingress_protects_detected_email(runtime, lease):
    raw = "Contact max.mustermann@example.de about the claim."
    protected = runtime.protect_text(raw, lease)
    assert "max.mustermann@example.de" not in protected
    assert "BBM1H.EMAIL." in protected
