from app.services.header_analyzer import analyze_headers


def test_authentication_results_and_dkim_fields():
    raw = b"""From: Security <security@example.com>\nReply-To: help@other.example\nReturn-Path: <bounce@mailer.example>\nMessage-ID: <abc@example.com>\nAuthentication-Results: mx.example; spf=fail smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=fail header.from=example.com; p=reject\nDKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail; bh=x; b=y\n\nBody\n"""
    result = analyze_headers(raw)
    assert result.authentication.spf_result == "fail"
    assert result.authentication.dkim_result == "pass"
    assert result.authentication.dmarc_result == "fail"
    assert result.authentication.spf_domain == "example.com"
    assert result.dkim_signatures[0]["d"] == "example.com"
    assert result.from_reply_to_mismatch is True
    assert result.from_return_path_mismatch is True


def test_received_headers_are_reversed_to_earliest_first_and_public_hop_selected():
    raw = b"""From: a@example.com\nReceived: from mx.example (mx.example [192.168.1.10]) by final.example; Mon, 31 Aug 2026 10:02:00 +0000\nReceived: from sender.example (sender.example [8.8.8.8]) by mx.example; Mon, 31 Aug 2026 10:01:00 +0000\n\nBody\n"""
    result = analyze_headers(raw)
    assert len(result.routing_hops) == 2
    assert result.routing_hops[0].source_ip == "8.8.8.8"
    assert result.routing_hops[0].is_public_ip is True
    assert result.earliest_reliable_sending_node is not None
    assert result.earliest_reliable_sending_node.source_ip == "8.8.8.8"


def test_missing_authentication_is_unknown_not_failure():
    result = analyze_headers(b"From: a@example.com\n\nhello")
    assert result.authentication.spf_result == "unknown"
    assert result.authentication.dkim_result == "unknown"
    assert result.authentication.dmarc_result == "unknown"
    assert result.routing_hops == []
