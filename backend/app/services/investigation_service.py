from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Analysis, AuthenticationResult, Domain, Email, EmailHeader, Indicator, IPAddress, ReceivedHop, URL
from app.services.ai_service import AIResult, analyze_text
from app.services.domain_analyzer import analyze_domain
from app.services.email_parser import ParsedEmail, parse_email
from app.services.email_storage import absolute_storage_path
from app.services.header_analyzer import HeaderForensicsResult, analyze_headers
from app.services.ip_analyzer import analyze_ip
from app.services.risk_engine import RiskEvidence, RiskResult, calculate_risk
from app.services.url_analyzer import analyze_url
from app.services.persistence_service import persist_analysis_result


@dataclass(slots=True)
class InvestigationResult:
    analysis_id: int
    status: str
    classification: str
    risk: RiskResult
    ai: AIResult
    parsed: ParsedEmail
    forensics: HeaderForensicsResult
    modules: dict[str, bool]


class InvestigationServiceError(Exception):
    pass


async def _load_raw_email(email: Email) -> bytes:
    if not email.raw_email_path:
        raise InvestigationServiceError("Stored raw email is unavailable")
    path = absolute_storage_path(email.raw_email_path)
    if not path.exists() or not path.is_file():
        raise InvestigationServiceError("Stored raw email file was not found")
    return path.read_bytes()


def _sender_domain(sender: str | None) -> str | None:
    if not sender or "@" not in sender:
        return None
    return sender.rsplit("@", 1)[-1].strip().lower().strip("<>")


def _evidence_from_forensics(result: HeaderForensicsResult) -> list[RiskEvidence]:
    evidence: list[RiskEvidence] = []
    if result.from_reply_to_mismatch:
        evidence.append(RiskEvidence("authentication_header", "high", title="From/Reply-To mismatch", reason="From and Reply-To domains differ"))
    if result.from_return_path_mismatch:
        evidence.append(RiskEvidence("authentication_header", "high", title="From/Return-Path mismatch", reason="From and Return-Path domains differ"))
    if result.message_id_domain_consistent is False:
        evidence.append(RiskEvidence("authentication_header", "medium", title="Message-ID mismatch", reason="Message-ID domain is inconsistent with the From domain"))
    auth = result.authentication
    if auth.spf_result == "fail":
        evidence.append(RiskEvidence("authentication_header", "high", title="SPF failure", reason="SPF authentication failed"))
    if auth.dkim_result == "fail":
        evidence.append(RiskEvidence("authentication_header", "high", title="DKIM failure", reason="DKIM authentication reported failure"))
    if auth.dmarc_result == "fail":
        evidence.append(RiskEvidence("authentication_header", "critical", title="DMARC failure", reason="DMARC authentication failed"))
    return evidence


def _indicator_rows(result: HeaderForensicsResult, ai: AIResult, risk: RiskResult, url_rows: list[URL], domain_rows: list[Domain], ip_rows: list[IPAddress]) -> list[dict]:
    rows: list[dict] = []
    for reason in result.findings:
        severity = "high" if any(x in reason.lower() for x in ("failed", "differ", "inconsistent")) else "medium"
        rows.append({"category": "header", "severity": severity, "title": "Header forensic finding", "description": reason, "evidence": reason, "score": 0})
    for item in ai.indicators:
        rows.append({"category": "nlp", "severity": "high" if item.type in {"credential_request", "financial_request"} else "medium", "title": item.type.replace("_", " ").title(), "description": item.description, "evidence": None, "score": 0})
    for item in url_rows:
        if item.is_suspicious:
            rows.append({"category": "url", "severity": "high" if (item.risk_score or 0) >= 60 else "medium", "title": "Suspicious URL", "description": item.reason or "Suspicious URL characteristics detected", "evidence": item.normalized_url, "score": item.risk_score or 0})
    for item in domain_rows:
        if item.is_suspicious:
            rows.append({"category": "domain", "severity": "high", "title": "Suspicious domain", "description": "Domain has suspicious characteristics", "evidence": item.domain, "score": item.risk_score or 0})
    for item in ip_rows:
        if (item.risk_score or 0) > 0:
            rows.append({"category": "ip", "severity": "medium", "title": "IP infrastructure finding", "description": "Non-public or reserved IP characteristic detected", "evidence": item.ip, "score": item.risk_score or 0})
    return rows


async def run_investigation(db: AsyncSession, email_id: int, user_id: int) -> InvestigationResult:
    """Run the complete passive investigation pipeline for one owned email."""
    email = await db.scalar(select(Email).where(Email.id == email_id, Email.user_id == user_id))
    if email is None:
        raise InvestigationServiceError("Email not found")

    raw = await _load_raw_email(email)
    analysis = Analysis(email_id=email.id, classification="unknown", risk_score=0, confidence=0.0, status="processing")
    db.add(analysis)
    await db.flush()

    modules = {"parser": False, "header_forensics": False, "intelligence": False, "ai": False, "risk": False, "persistence": False}
    try:
        # 1. Parse email
        parsed = parse_email(raw)
        modules["parser"] = True
        email.message_id = parsed.message_id
        email.sender = parsed.sender
        email.recipient = ", ".join(parsed.recipients) if parsed.recipients else None
        email.reply_to = parsed.reply_to
        email.return_path = parsed.return_path
        email.subject = parsed.subject
        email.body_text = parsed.body_text
        email.body_html = parsed.body_html
        email.received_at = parsed.date

        # Rebuild parser-derived rows deterministically.
        for model in (EmailHeader, ReceivedHop, URL, Domain, IPAddress):
            await db.execute(delete(model).where(model.email_id == email.id))
        for name, value in parsed.headers:
            db.add(EmailHeader(email_id=email.id, header_name=name, header_value=value))
        for hop in analyze_headers(raw).routing_hops:
            db.add(ReceivedHop(email_id=email.id, hop_order=hop.hop_order, raw_received_header=hop.raw_received_header,
                               source_ip=hop.source_ip, source_hostname=hop.source_hostname, destination_hostname=hop.destination_hostname,
                               timestamp=hop.timestamp, is_private_ip=hop.is_private_ip, is_public_ip=hop.is_public_ip, is_reliable=hop.is_reliable))
        for u in parsed.urls:
            db.add(URL(email_id=email.id, url=u.url, normalized_url=u.normalized_url, domain=u.domain, scheme=u.scheme, port=u.port, path=u.path))
        for ip in parsed.ip_addresses:
            result = analyze_ip(ip)
            db.add(IPAddress(email_id=email.id, ip=ip, ip_version=result.ip_version, is_private=result.is_private, risk_score=result.risk_score))

        # 2. Header/authentication forensics
        forensics = analyze_headers(raw)
        modules["header_forensics"] = True
        await db.execute(delete(AuthenticationResult).where(AuthenticationResult.email_id == email.id))
        auth = forensics.authentication
        db.add(AuthenticationResult(email_id=email.id, spf_result=auth.spf_result, dkim_result=auth.dkim_result,
                                    dmarc_result=auth.dmarc_result, spf_domain=auth.spf_domain, dkim_domain=auth.dkim_domain,
                                    dmarc_policy=auth.dmarc_policy, raw_authentication_header=auth.raw_authentication_header))

        # 3. Passive URL/domain/IP intelligence
        urls = list((await db.scalars(select(URL).where(URL.email_id == email.id))).all())
        domains_by_name: dict[str, Domain] = {}
        for item in urls:
            u = analyze_url(item.url)
            item.normalized_url, item.domain, item.scheme, item.port, item.path = u.normalized_url, u.domain, u.scheme, u.port, u.path
            item.is_shortened, item.is_suspicious, item.risk_score, item.classification, item.reason = u.is_shortened, u.is_suspicious, u.risk_score, u.classification, u.reason
            if item.domain and item.domain not in domains_by_name:
                d = Domain(email_id=email.id, domain=item.domain)
                db.add(d); domains_by_name[item.domain] = d
        await db.flush()
        domains = list(domains_by_name.values())
        sender_domain = _sender_domain(email.sender)
        for item in domains:
            d = analyze_domain(item.domain, sender_domain)
            item.is_lookalike, item.is_suspicious, item.risk_score = d.is_lookalike, d.is_suspicious, d.risk_score
        ips = list((await db.scalars(select(IPAddress).where(IPAddress.email_id == email.id))).all())
        for item in ips:
            p = analyze_ip(item.ip); item.ip_version, item.is_private, item.risk_score = p.ip_version, p.is_private, p.risk_score
        modules["intelligence"] = True

        # 4. AI/NLP
        ai = await analyze_text(email.subject, email.body_text or email.body_html)
        modules["ai"] = ai.status == "completed"

        # 5. Risk engine — AI plus all other observed/inferred signals.
        evidence = _evidence_from_forensics(forensics)
        if ai.phishing_probability >= 0.7:
            evidence.append(RiskEvidence("ai_nlp", "critical", contribution=30, title="High phishing probability", reason="AI analysis indicates a high phishing probability"))
        elif ai.phishing_probability >= 0.45:
            evidence.append(RiskEvidence("ai_nlp", "high", contribution=22, title="Elevated phishing probability", reason="AI analysis indicates elevated phishing probability"))
        for indicator in ai.indicators:
            if indicator.type in {"urgency", "credential_request", "financial_request"}:
                evidence.append(RiskEvidence("social_engineering", "high", reason=indicator.description, title=indicator.type))
        for item in urls:
            if item.is_suspicious:
                evidence.append(RiskEvidence("url", "high", contribution=min(20, float(item.risk_score or 0) * 0.2), reason=item.reason or "Suspicious URL detected"))
        for item in domains:
            if item.is_suspicious:
                evidence.append(RiskEvidence("domain", "high", contribution=min(10, float(item.risk_score or 0) * 0.1), reason="Suspicious domain characteristics detected"))
        for item in ips:
            if item.risk_score:
                evidence.append(RiskEvidence("ip_infrastructure", "medium", contribution=min(10, float(item.risk_score) * 0.1), reason=f"IP infrastructure finding for {item.ip}"))
        risk = calculate_risk(evidence, ai_confidence=ai.confidence, module_availability=modules)
        modules["risk"] = True

        # Persist analysis + explainable indicators atomically.
        classification = ai.classification if ai.classification != "unknown" else ("suspicious" if risk.risk_score >= 41 else "unknown")
        await persist_analysis_result(
            db,
            analysis,
            classification=classification,
            risk_score=risk.risk_score,
            confidence=risk.confidence,
            summary="; ".join(risk.reasons[:8]) or "No significant risk indicators were observed.",
            indicators=_indicator_rows(forensics, ai, risk, urls, domains, ips),
        )
        await db.commit()
        modules["persistence"] = True
        return InvestigationResult(analysis.id, analysis.status, analysis.classification, risk, ai, parsed, forensics, modules)
    except Exception:
        await db.rollback()
        raise
