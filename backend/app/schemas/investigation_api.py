from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class InvestigationListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    analysis_id: int
    email_id: int
    classification: str
    risk_score: int
    risk_level: str
    confidence: float
    status: str
    subject: str | None = None
    sender: str | None = None
    created_at: datetime
    completed_at: datetime | None = None

class InvestigationListResponse(BaseModel):
    items: list[InvestigationListItem]
    page: int
    page_size: int
    total: int

class IndicatorResponse(BaseModel):
    id: int
    category: str
    severity: str
    title: str
    description: str
    evidence: str | None = None
    score_contribution: int
    created_at: datetime

class AuthenticationResponse(BaseModel):
    spf: str
    dkim: str
    dmarc: str
    spf_domain: str | None = None
    dkim_domain: str | None = None
    dmarc_policy: str | None = None

class RoutingHopResponse(BaseModel):
    hop: int
    raw_received_header: str
    source_ip: str | None = None
    source_hostname: str | None = None
    destination_hostname: str | None = None
    timestamp: datetime | None = None
    is_private_ip: bool
    is_public_ip: bool
    is_reliable: bool

class URLResponse(BaseModel):
    id: int
    url: str
    normalized_url: str | None
    domain: str | None
    scheme: str | None
    port: int | None
    path: str | None
    is_shortened: bool
    is_suspicious: bool
    risk_score: int | None
    classification: str | None
    reason: str | None

class DomainResponse(BaseModel):
    id: int
    domain: str
    domain_age: int | None
    registrar: str | None
    reputation: str | None
    is_lookalike: bool
    is_suspicious: bool
    risk_score: int | None

class IPResponse(BaseModel):
    id: int
    ip: str
    ip_version: int | None
    country: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    isp: str | None
    organization: str | None
    asn: str | None
    hosting_provider: str | None
    is_vpn: bool | None
    is_proxy: bool | None
    is_tor: bool | None
    is_private: bool
    reputation: str | None
    risk_score: int | None

class InvestigationDetailResponse(BaseModel):
    analysis: dict[str, Any]
    email: dict[str, Any]
    authentication: AuthenticationResponse | None
    headers: list[dict[str, Any]]
    routing: dict[str, Any]
    urls: list[URLResponse]
    domains: list[DomainResponse]
    ips: list[IPResponse]
    indicators: list[IndicatorResponse]
    geolocation: dict[str, Any]
    risk: dict[str, Any]
    graph: dict[str, Any]
