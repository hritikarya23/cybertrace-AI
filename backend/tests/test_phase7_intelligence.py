from app.services.url_analyzer import analyze_url
from app.services.domain_analyzer import analyze_domain
from app.services.ip_analyzer import analyze_ip


def test_url_ip_and_credentials_are_suspicious():
    r = analyze_url("http://192.0.2.10/login?x=%2Fsecret")
    assert r.is_suspicious
    assert r.domain == "192.0.2.10"
    assert r.risk_score >= 40


def test_shortener_is_detected():
    r = analyze_url("https://bit.ly/abc")
    assert r.is_shortened
    assert "shortening service" in (r.reason or "")


def test_punycode_domain():
    r = analyze_domain("xn--example-9za.com")
    assert r.risk_score >= 25


def test_lookalike_with_configured_brand(monkeypatch):
    monkeypatch.setenv("TRUSTED_BRANDS", "PayPal:paypal.com")
    r = analyze_domain("paypa1.com")
    assert r.is_lookalike
    assert r.target_brand == "paypal"


def test_private_ip_never_public():
    r = analyze_ip("192.168.1.5")
    assert r.is_private
    assert not r.is_public
