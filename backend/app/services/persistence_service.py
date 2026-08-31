from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Analysis, AuthenticationResult, Domain, Email, EmailHeader, Indicator, IPAddress, ReceivedHop, URL


class PersistenceError(RuntimeError):
    """Raised when an investigation cannot be persisted atomically."""


@asynccontextmanager
async def transaction(session: AsyncSession) -> AsyncIterator[AsyncSession]:
    """Provide an explicit transaction boundary and rollback on failure."""
    try:
        async with session.begin():
            yield session
    except SQLAlchemyError as exc:
        # SQLAlchemy rolls back the transaction automatically; explicitly
        # rollback also makes the contract safe if the caller reuses session.
        await session.rollback()
        raise PersistenceError("Database transaction failed") from exc


async def get_analysis_for_update(session: AsyncSession, analysis_id: int) -> Analysis | None:
    """Load an analysis row for a caller that intends to update it."""
    result = await session.execute(
        select(Analysis).where(Analysis.id == analysis_id).with_for_update()
    )
    return result.scalar_one_or_none()


async def replace_derived_email_data(
    session: AsyncSession,
    email: Email,
    headers: list[tuple[str, str]],
    hops: list,
    parsed_urls: list,
    parsed_ips: list[dict],
) -> None:
    """Replace parser-derived rows deterministically inside the active transaction."""
    for model in (EmailHeader, ReceivedHop, URL, Domain, IPAddress, AuthenticationResult):
        await session.execute(delete(model).where(model.email_id == email.id))

    session.add_all([
        EmailHeader(email_id=email.id, header_name=name, header_value=value)
        for name, value in headers
    ])
    session.add_all([
        ReceivedHop(
            email_id=email.id,
            hop_order=hop.hop_order,
            raw_received_header=hop.raw_received_header,
            source_ip=hop.source_ip,
            source_hostname=hop.source_hostname,
            destination_hostname=hop.destination_hostname,
            timestamp=hop.timestamp,
            is_private_ip=hop.is_private_ip,
            is_public_ip=hop.is_public_ip,
            is_reliable=hop.is_reliable,
        )
        for hop in hops
    ])
    session.add_all([
        URL(
            email_id=email.id,
            url=item.url,
            normalized_url=item.normalized_url,
            domain=item.domain,
            scheme=item.scheme,
            port=item.port,
            path=item.path,
            is_shortened=item.is_shortened,
            is_suspicious=item.is_suspicious,
            risk_score=item.risk_score,
            classification=item.classification,
            reason=item.reason,
        )
        for item in parsed_urls
    ])
    session.add_all([
        IPAddress(email_id=email.id, **row) for row in parsed_ips
    ])


async def persist_analysis_result(
    session: AsyncSession,
    analysis: Analysis,
    *,
    classification: str,
    risk_score: int,
    confidence: float,
    summary: str,
    indicators: list[dict],
) -> Analysis:
    """Persist the final analysis and its indicators in one transaction."""
    analysis.classification = classification
    analysis.risk_score = max(0, min(100, int(risk_score)))
    analysis.confidence = max(0.0, min(1.0, float(confidence)))
    analysis.status = "completed"
    analysis.summary = summary
    analysis.completed_at = datetime.now(timezone.utc)

    await session.execute(delete(Indicator).where(Indicator.analysis_id == analysis.id))
    session.add_all([
        Indicator(
            analysis_id=analysis.id,
            category=item["category"],
            severity=item["severity"],
            title=item["title"],
            description=item["description"],
            evidence=item.get("evidence"),
            score_contribution=int(item.get("score", 0)),
        )
        for item in indicators
    ])
    await session.flush()
    return analysis
