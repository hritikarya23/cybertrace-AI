from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.dependencies import get_current_user
from app.database.database import get_db
from app.database.models import (
    Analysis, AuthenticationResult, Domain, Email, EmailHeader, GraphEdge, GraphNode,
    Indicator, IPAddress, ReceivedHop, URL, User,
)
from app.schemas.investigation_api import (
    IndicatorResponse, InvestigationDetailResponse, InvestigationListItem,
    InvestigationListResponse,
)

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])


def risk_level(score: int) -> str:
    if score <= 20:
        return "low"
    if score <= 40:
        return "medium"
    if score <= 60:
        return "elevated"
    if score <= 80:
        return "high"
    return "critical"


async def owned_analysis(db: AsyncSession, analysis_id: int, user: User) -> Analysis | None:
    stmt = (
        select(Analysis)
        .join(Email, Email.id == Analysis.email_id)
        .where(Analysis.id == analysis_id, Email.user_id == user.id)
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


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    classification: str | None = Query(None, min_length=1, max_length=64),
    risk_level_filter: str | None = Query(None, alias="risk_level", pattern="^(low|medium|elevated|high|critical)$"),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    search: str | None = Query(None, min_length=1, max_length=200),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    conditions = [Email.user_id == user.id]
    if classification:
        conditions.append(Analysis.classification == classification.lower())
    if date_from:
        conditions.append(Analysis.created_at >= date_from)
    if date_to:
        conditions.append(Analysis.created_at <= date_to)
    if search:
        term = f"%{search.strip()}%"
        conditions.append(or_(Email.sender.ilike(term), Email.subject.ilike(term), Email.message_id.ilike(term)))

    # Risk level is derived from score, not stored, so translate it to score bounds.
    bounds = {"low": (0, 20), "medium": (21, 40), "elevated": (41, 60), "high": (61, 80), "critical": (81, 100)}
    if risk_level_filter:
        lo, hi = bounds[risk_level_filter]
        conditions.extend([Analysis.risk_score >= lo, Analysis.risk_score <= hi])

    base = select(Analysis).join(Email, Email.id == Analysis.email_id).where(and_(*conditions))
    total = await db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = (await db.scalars(base.order_by(Analysis.created_at.desc()).offset((page - 1) * page_size).limit(page_size))).all()

    items = [InvestigationListItem(
        analysis_id=a.id, email_id=a.email_id, classification=a.classification,
        risk_score=a.risk_score, risk_level=risk_level(a.risk_score), confidence=a.confidence,
        status=a.status, subject=None, sender=None, created_at=a.created_at, completed_at=a.completed_at,
    ) for a in rows]
    # Avoid lazy loading: fetch email metadata in one query.
    if rows:
        emails = (await db.scalars(select(Email).where(Email.id.in_([a.email_id for a in rows])))).all()
        by_id = {e.id: e for e in emails}
        for item in items:
            e = by_id.get(item.email_id)
            if e:
                item.subject, item.sender = e.subject, e.sender
    return InvestigationListResponse(items=items, page=page, page_size=page_size, total=total)


@router.get("/{analysis_id}", response_model=InvestigationDetailResponse)
async def get_investigation(
    analysis_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    analysis = await owned_analysis(db, analysis_id, user)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    email = analysis.email
    auth = email.authentication_result
    hops = sorted(email.received_hops, key=lambda x: x.hop_order)

    # Graph is reconstructed from persisted graph tables; no Neo4j dependency is required.
    node_map = {n.id: n for n in analysis.graph_nodes}
    graph = {
        "nodes": [
            {"id": f"{n.node_type}:{n.node_value}", "label": n.node_value, "type": n.node_type, "metadata": n.metadata_json or {}}
            for n in analysis.graph_nodes
        ],
        "edges": [
            {
                "source": f"{node_map[e.source_node_id].node_type}:{node_map[e.source_node_id].node_value}" if e.source_node_id in node_map else str(e.source_node_id),
                "target": f"{node_map[e.target_node_id].node_type}:{node_map[e.target_node_id].node_value}" if e.target_node_id in node_map else str(e.target_node_id),
                "relationship": e.relationship_type,
                "metadata": e.metadata_json or {},
            }
            for e in analysis.graph_edges
        ],
    }
    geo = {
        "status": "available" if any(i.country or i.latitude is not None for i in email.ip_addresses) else "unavailable",
        "estimated": True,
        "ips": [{"ip": i.ip, "country": i.country, "region": i.region, "city": i.city, "latitude": i.latitude, "longitude": i.longitude, "attribution_confidence": None} for i in email.ip_addresses],
    }
    reasons = [i.description for i in analysis.indicators if i.description]
    return InvestigationDetailResponse(
        analysis={"id": analysis.id, "email_id": analysis.email_id, "classification": analysis.classification,
                  "risk_score": analysis.risk_score, "risk_level": risk_level(analysis.risk_score),
                  "confidence": analysis.confidence, "status": analysis.status, "summary": analysis.summary,
                  "created_at": analysis.created_at, "completed_at": analysis.completed_at},
        email={"id": email.id, "sender": email.sender, "recipient": email.recipient, "reply_to": email.reply_to,
               "return_path": email.return_path, "subject": email.subject, "message_id": email.message_id,
               "received_at": email.received_at},
        authentication=(None if auth is None else {"spf": auth.spf_result, "dkim": auth.dkim_result, "dmarc": auth.dmarc_result,
            "spf_domain": auth.spf_domain, "dkim_domain": auth.dkim_domain, "dmarc_policy": auth.dmarc_policy}),
        headers=[{"name": h.header_name, "value": h.header_value} for h in email.headers],
        routing={"hops": [{"hop": h.hop_order, "raw_received_header": h.raw_received_header, "source_ip": h.source_ip,
                           "source_hostname": h.source_hostname, "destination_hostname": h.destination_hostname,
                           "timestamp": h.timestamp, "is_private_ip": h.is_private_ip, "is_public_ip": h.is_public_ip,
                           "is_reliable": h.is_reliable} for h in hops],
                 "earliest_reliable_node": next(({"hop": h.hop_order, "ip": h.source_ip, "hostname": h.source_hostname} for h in hops if h.is_reliable), None)},
        urls=[u for u in email.urls], domains=[d for d in email.domains], ips=[i for i in email.ip_addresses],
        indicators=[i for i in analysis.indicators], geolocation=geo,
        risk={"risk_score": analysis.risk_score, "risk_level": risk_level(analysis.risk_score), "confidence": analysis.confidence, "reasons": reasons[:20]},
        graph=graph,
    )


@router.get("/{analysis_id}/indicators", response_model=list[IndicatorResponse])
async def get_indicators(
    analysis_id: int,
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    category: str | None = Query(None, min_length=1, max_length=64),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    exists = await db.scalar(select(Analysis.id).join(Email).where(Analysis.id == analysis_id, Email.user_id == user.id))
    if exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    conditions = [Indicator.analysis_id == analysis_id]
    if severity:
        conditions.append(Indicator.severity == severity)
    if category:
        conditions.append(Indicator.category == category.lower())
    rows = (await db.scalars(select(Indicator).where(and_(*conditions)).order_by(Indicator.created_at.desc()))).all()
    return [IndicatorResponse.model_validate(i) for i in rows]
