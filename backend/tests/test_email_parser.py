from app.services.email_parser import parse_email


def test_parse_simple_multipart_email():
    raw = b"""From: Security <security@example.com>\nTo: analyst@example.net\nReply-To: replies@other.example\nSubject: Test message\nDate: Mon, 31 Aug 2026 12:00:00 +0000\nMessage-ID: <abc@example.com>\nReceived: from mail.example.com (203.0.113.10) by mx.example.net; Mon, 31 Aug 2026 12:00:00 +0000\nAuthentication-Results: mx.example.net; spf=pass\nContent-Type: multipart/mixed; boundary=XYZ\n\n--XYZ\nContent-Type: text/plain; charset=utf-8\n\nVisit https://example.com/login and https://example.com/login.\n\n--XYZ\nContent-Type: text/html; charset=utf-8\n\n<a href='https://example.org/path'>Open</a>\n--XYZ\nContent-Type: text/plain\nContent-Disposition: attachment; filename=note.txt\n\nhello\n--XYZ--\n"""
    result = parse_email(raw)
    assert result.sender == "security@example.com"
    assert result.recipients == ["analyst@example.net"]
    assert result.reply_to == "replies@other.example"
    assert result.message_id == "<abc@example.com>"
    assert len(result.urls) == 2
    assert "203.0.113.10" in result.ip_addresses
    assert len(result.attachments) == 1
    assert result.attachments[0].filename == "note.txt"


def test_malformed_date_does_not_crash():
    result = parse_email(b"From: a@example.com\nDate: definitely-not-a-date\n\nhello")
    assert result.sender == "a@example.com"
    assert result.date is None


def test_no_attachment_contents_are_exposed_as_body():
    raw = b"From: a@example.com\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nvisible\n--x\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=sample.bin\n\nSECRET-BYTES\n--x--\n"
    result = parse_email(raw)
    assert "visible" in result.body_text
    assert "SECRET-BYTES" not in result.body_text
    assert result.attachments[0].size > 0
