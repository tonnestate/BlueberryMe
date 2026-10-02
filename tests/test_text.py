def test_fallback_detector_removes_email_and_secret(runtime, lease):
    text = "Mail max@example.de; token github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    protected = runtime.protect_text(text, lease)
    assert "max@example.de" not in protected
    assert "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" not in protected
