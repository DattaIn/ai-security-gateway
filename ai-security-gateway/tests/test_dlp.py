from ai_security_gateway.detectors.dlp import scan_and_redact


def test_clean_text_has_no_findings():
    result = scan_and_redact("What is the capital of France?")
    assert result.findings == []
    assert result.has_critical is False


def test_aws_key_detected_and_redacted():
    text = "My key is AKIAABCDEFGHIJKLMNOP, please use it."
    result = scan_and_redact(text)
    assert result.has_critical is True
    assert "AKIAABCDEFGHIJKLMNOP" not in result.redacted_text
    assert "[REDACTED_AWS_KEY]" in result.redacted_text


def test_private_key_block_detected():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIExampleKeyData\n-----END RSA PRIVATE KEY-----"
    result = scan_and_redact(text)
    assert result.has_critical is True
    assert "[REDACTED_PRIVATE_KEY]" in result.redacted_text


def test_email_redacted_as_medium_severity():
    result = scan_and_redact("Contact me at jane.doe@example.com for details.")
    assert result.has_critical is False
    assert "[REDACTED_EMAIL]" in result.redacted_text


def test_jwt_detected_and_redacted():
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
    result = scan_and_redact(f"Here is a token: {fake_jwt}")
    assert result.has_critical is True
    assert fake_jwt not in result.redacted_text


def test_multiple_findings_reported_independently():
    text = "Email jane@example.com and key AKIAABCDEFGHIJKLMNOP"
    result = scan_and_redact(text)
    names = {f.rule_name for f in result.findings}
    assert "email" in names
    assert "aws_access_key" in names
