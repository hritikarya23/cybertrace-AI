from app.services.risk_engine import RiskEvidence, calculate_risk


def test_clean_email_is_low_and_confidence_is_independent():
    result = calculate_risk([], module_availability={
        "ai_nlp": True, "authentication_header": True, "url": True,
        "domain": True, "ip_infrastructure": True, "social_engineering": True,
    })
    assert result.risk_score == 0
    assert result.risk_level == "low"
    assert 0.0 <= result.confidence <= 1.0


def test_category_caps_prevent_double_counting():
    evidence = [
        RiskEvidence("url", "critical", contribution=100, reason="Suspicious URL"),
        RiskEvidence("url", "critical", contribution=100, reason="Another URL"),
    ]
    result = calculate_risk(evidence)
    assert result.category_scores["url"] == 20.0
    assert result.risk_score == 20


def test_strong_cross_category_evidence_reaches_critical():
    evidence = [
        RiskEvidence("ai_nlp", "critical", contribution=30, reason="High phishing probability"),
        RiskEvidence("authentication_header", "critical", contribution=20, reason="DMARC failed"),
        RiskEvidence("url", "critical", contribution=20, reason="Credential URL detected"),
        RiskEvidence("domain", "high", contribution=10, reason="Look-alike domain"),
        RiskEvidence("ip_infrastructure", "high", contribution=10, reason="Risky infrastructure"),
        RiskEvidence("social_engineering", "high", contribution=10, reason="Urgency detected"),
    ]
    result = calculate_risk(evidence, ai_confidence=0.96)
    assert result.risk_score == 100
    assert result.risk_level == "critical"
    assert result.confidence > 0.8


def test_custom_weights_are_normalized():
    result = calculate_risk(
        [RiskEvidence("ai_nlp", "critical", contribution=100, reason="AI")],
        weights={"ai_nlp": 60, "authentication_header": 10, "url": 10, "domain": 10, "ip_infrastructure": 5, "social_engineering": 5},
    )
    assert result.category_scores["ai_nlp"] == 60.0
    assert result.risk_score == 60
    assert result.risk_level == "elevated"
