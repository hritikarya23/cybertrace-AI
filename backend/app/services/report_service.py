from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select

from app.config import settings
from app.database.models import Analysis, Email, Report


def _safe(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return html.escape(str(value))


def _risk_level(score: int) -> str:
    if score <= 20: return "LOW"
    if score <= 40: return "MEDIUM"
    if score <= 60: return "ELEVATED"
    if score <= 80: return "HIGH"
    return "CRITICAL"


async def load_analysis_for_report(db: AsyncSession, analysis_id: int, user_id: int) -> Analysis | None:
    stmt = (
        select(Analysis)
        .join(Email, Email.id == Analysis.email_id)
        .where(Analysis.id == analysis_id, Email.user_id == user_id)
        .options(
            selectinload(Analysis.email).selectinload(Email.headers),
            selectinload(Analysis.email).selectinload(Email.received_hops),
            selectinload(Analysis.email).selectinload(Email.urls),
            selectinload(Analysis.email).selectinload(Email.domains),
            selectinload(Analysis.email).selectinload(Email.ip_addresses),
            selectinload(Analysis.email).selectinload(Email.authentication_result),
            selectinload(Analysis.indicators),
            selectinload(Analysis.graph_nodes),
            selectinload(Analysis.graph_edges),
        )
    )
    return await db.scalar(stmt)


def build_report_context(analysis: Analysis, analyst: str) -> dict[str, Any]:
    email = analysis.email
    auth = email.authentication_result
    hops = sorted(email.received_hops, key=lambda x: x.hop_order)
    reliable = next((h for h in hops if h.is_reliable), None)
    return {
        "investigation_id": analysis.id,
        "generated_at": datetime.now(timezone.utc),
        "analyst": analyst,
        "email": email,
        "analysis": analysis,
        "auth": auth,
        "hops": hops,
        "earliest_reliable": reliable,
        "risk_level": _risk_level(analysis.risk_score),
        "indicators": sorted(analysis.indicators, key=lambda x: (x.severity, x.created_at), reverse=True),
        "nodes": analysis.graph_nodes,
        "edges": analysis.graph_edges,
    }


def render_html(context: dict[str, Any]) -> str:
    a = context["analysis"]
    e = context["email"]
    auth = context["auth"]
    reliable = context["earliest_reliable"]
    hops = context["hops"]
    indicators = context["indicators"]
    nodes = context["nodes"]
    edges = context["edges"]

    auth_rows = "".join(
        f"<tr><th>{name}</th><td>{_safe(getattr(auth, attr, None) if auth else None).upper()}</td></tr>"
        for name, attr in (("SPF", "spf_result"), ("DKIM", "dkim_result"), ("DMARC", "dmarc_result"))
    )
    indicator_rows = "".join(
        f"<tr><td>{_safe(i.category)}</td><td>{_safe(i.severity).upper()}</td><td>{_safe(i.title)}</td>"
        f"<td>{_safe(i.description)}</td><td>{_safe(i.evidence)}</td><td>{_safe(i.score_contribution)}</td></tr>"
        for i in indicators
    ) or '<tr><td colspan="6">No indicators recorded.</td></tr>'
    hop_rows = "".join(
        f"<tr><td>{h.hop_order}</td><td>{_safe(h.source_hostname)}</td><td>{_safe(h.source_ip)}</td>"
        f"<td>{_safe(h.destination_hostname)}</td><td>{_safe(h.timestamp)}</td><td>{'Yes' if h.is_reliable else 'No'}</td></tr>"
        for h in hops
    ) or '<tr><td colspan="6">No routing hops recorded.</td></tr>'
    url_rows = "".join(
        f"<tr><td>{_safe(u.normalized_url or u.url)}</td><td>{_safe(u.domain)}</td><td>{'Yes' if u.is_suspicious else 'No'}</td>"
        f"<td>{_safe(u.risk_score)}</td><td>{_safe(u.reason)}</td></tr>" for u in e.urls
    ) or '<tr><td colspan="5">No URLs recorded.</td></tr>'
    domain_rows = "".join(
        f"<tr><td>{_safe(d.domain)}</td><td>{'Yes' if d.is_lookalike else 'No'}</td><td>{'Yes' if d.is_suspicious else 'No'}</td>"
        f"<td>{_safe(d.reputation)}</td><td>{_safe(d.risk_score)}</td></tr>" for d in e.domains
    ) or '<tr><td colspan="5">No domains recorded.</td></tr>'
    ip_rows = "".join(
        f"<tr><td>{_safe(i.ip)}</td><td>{_safe(i.country)}</td><td>{_safe(i.region)}</td><td>{_safe(i.city)}</td>"
        f"<td>{_safe(i.latitude)}, {_safe(i.longitude)}</td><td>{_safe(i.asn)}</td><td>{'Yes' if i.is_private else 'No'}</td></tr>" for i in e.ip_addresses
    ) or '<tr><td colspan="7">No IP intelligence recorded.</td></tr>'

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Forensic Report #{a.id}</title>
<style>
body{{font-family:Arial,sans-serif;color:#172033;margin:36px;line-height:1.45}} h1{{margin-bottom:4px}} h2{{border-bottom:2px solid #ddd;padding-bottom:5px;margin-top:28px}} table{{width:100%;border-collapse:collapse;margin:10px 0 18px;font-size:12px}} th,td{{border:1px solid #d8dde6;padding:6px;text-align:left;vertical-align:top}} th{{background:#f3f5f8}} .score{{font-size:30px;font-weight:700}} .muted{{color:#5d6675}} .warning{{background:#fff8e6;padding:10px;border:1px solid #ead79a}} footer{{margin-top:35px;font-size:11px;color:#667}} 
</style></head><body>
<h1>AI Email Forensic Intelligence Report</h1><div class="muted">Investigation ID: #{a.id} · Generated: {_safe(context['generated_at'])}</div>
<h2>Executive Assessment</h2><div class="score">{a.risk_score}/100 — {_safe(context['risk_level'])}</div>
<p><b>Classification:</b> {_safe(a.classification).upper()} &nbsp; <b>Confidence:</b> {a.confidence:.2f} &nbsp; <b>Status:</b> {_safe(a.status)}</p>
<p>{_safe(a.summary)}</p>
<div class="warning"><b>Forensic attribution note:</b> IP geolocation and routing evidence represent observed or estimated infrastructure information. They do not establish an exact attacker identity or physical location.</div>
<h2>Email Metadata</h2><table><tr><th>Sender</th><td>{_safe(e.sender)}</td></tr><tr><th>Recipient</th><td>{_safe(e.recipient)}</td></tr><tr><th>Reply-To</th><td>{_safe(e.reply_to)}</td></tr><tr><th>Return-Path</th><td>{_safe(e.return_path)}</td></tr><tr><th>Subject</th><td>{_safe(e.subject)}</td></tr><tr><th>Message-ID</th><td>{_safe(e.message_id)}</td></tr><tr><th>Received At</th><td>{_safe(e.received_at)}</td></tr></table>
<h2>Authentication Results</h2><table><tr><th>Check</th><th>Result</th></tr>{auth_rows}</table>
<h2>Header & Routing Findings</h2><p><b>Earliest reliable sending node:</b> {_safe(reliable.source_hostname if reliable else None)} / {_safe(reliable.source_ip if reliable else None)}</p>
<table><tr><th>Hop</th><th>Source</th><th>IP</th><th>Destination</th><th>Timestamp</th><th>Reliable</th></tr>{hop_rows}</table>
<h2>Suspicious URLs</h2><table><tr><th>URL</th><th>Domain</th><th>Suspicious</th><th>Risk</th><th>Reason</th></tr>{url_rows}</table>
<h2>Domain Findings</h2><table><tr><th>Domain</th><th>Look-alike</th><th>Suspicious</th><th>Reputation</th><th>Risk</th></tr>{domain_rows}</table>
<h2>IP Intelligence & Estimated Geolocation</h2><table><tr><th>IP</th><th>Country</th><th>Region</th><th>City</th><th>Coordinates</th><th>ASN</th><th>Private</th></tr>{ip_rows}</table>
<h2>Risk Indicators</h2><table><tr><th>Category</th><th>Severity</th><th>Title</th><th>Description</th><th>Evidence</th><th>Contribution</th></tr>{indicator_rows}</table>
<h2>Relationship Graph Summary</h2><p><b>Nodes:</b> {len(nodes)} &nbsp; <b>Edges:</b> {len(edges)}</p>
<h2>Final Assessment</h2><p>{_safe(a.summary or 'Assessment based on the evidence available at analysis time.')}</p>
<footer>Prepared for forensic investigation. Observed evidence and inferred intelligence are intentionally distinguished; missing external intelligence is not fabricated.</footer>
</body></html>"""


def render_pdf(context: dict[str, Any], output_path: Path) -> None:
    a = context["analysis"]
    e = context["email"]
    auth = context["auth"]
    hops = context["hops"]
    reliable = context["earliest_reliable"]
    indicators = context["indicators"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    story = [Paragraph("AI Email Forensic Intelligence Report", styles["Title"]),
             Paragraph(f"Investigation ID: #{a.id}", styles["Normal"]), Spacer(1, 10)]
    story += [Paragraph("Executive Assessment", styles["Heading2"]),
              Paragraph(f"<b>Classification:</b> {_safe(a.classification).upper()} &nbsp; <b>Risk:</b> {a.risk_score}/100 ({_safe(context['risk_level'])}) &nbsp; <b>Confidence:</b> {a.confidence:.2f}", styles["Normal"]),
              Paragraph(_safe(a.summary), styles["BodyText"]), Spacer(1, 8)]
    story += [Paragraph("Email Metadata", styles["Heading2"]), _table([
        ["Sender", e.sender], ["Recipient", e.recipient], ["Reply-To", e.reply_to],
        ["Return-Path", e.return_path], ["Subject", e.subject], ["Message-ID", e.message_id],
    ])]
    story += [Paragraph("Authentication", styles["Heading2"]), _table([
        ["SPF", getattr(auth, "spf_result", None) if auth else None],
        ["DKIM", getattr(auth, "dkim_result", None) if auth else None],
        ["DMARC", getattr(auth, "dmarc_result", None) if auth else None],
    ])]
    story += [Paragraph("Routing", styles["Heading2"]), Paragraph(
        f"Earliest reliable sending node: {_safe(reliable.source_hostname if reliable else None)} / {_safe(reliable.source_ip if reliable else None)}", styles["BodyText"])]
    routing_data = [["Hop", "Source", "IP", "Destination", "Reliable"]] + [[h.hop_order, h.source_hostname, h.source_ip, h.destination_hostname, "Yes" if h.is_reliable else "No"] for h in hops]
    story.append(_table(routing_data))
    story += [Paragraph("Risk Indicators", styles["Heading2"])]
    indicator_data = [["Severity", "Category", "Title", "Contribution"]] + [[i.severity, i.category, i.title, i.score_contribution] for i in indicators]
    story.append(_table(indicator_data))
    story += [Paragraph("Attribution note: IP geolocation is estimated infrastructure intelligence and does not establish exact attacker identity or physical location.", styles["BodyText"])]
    SimpleDocTemplate(str(output_path), pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36).build(story)


def _table(rows: list[list[Any]]) -> Table:
    data = [[_safe(x) for x in row] for row in rows]
    table = Table(data, repeatRows=1 if len(data) > 1 else 0)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, "#cccccc"),
        ("BACKGROUND", (0, 0), (-1, 0), "#eeeeee"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


async def generate_report(db: AsyncSession, analysis_id: int, user_id: int, analyst: str, report_type: str) -> tuple[Path, Report] | None:
    analysis = await load_analysis_for_report(db, analysis_id, user_id)
    if analysis is None:
        return None
    context = build_report_context(analysis, analyst)
    report_dir = Path(settings.report_storage_path).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    stem = f"investigation_{analysis_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    if report_type == "html":
        path = report_dir / f"{stem}.html"
        path.write_text(render_html(context), encoding="utf-8")
    else:
        path = report_dir / f"{stem}.pdf"
        render_pdf(context, path)
    record = Report(analysis_id=analysis_id, report_type=report_type, file_path=str(path))
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return path, record
