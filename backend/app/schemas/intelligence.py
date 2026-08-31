from __future__ import annotations
from pydantic import BaseModel

class URLIntelligence(BaseModel):
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

class DomainIntelligence(BaseModel):
    id: int
    domain: str
    is_lookalike: bool
    target_brand: str | None
    confidence: float
    is_suspicious: bool
    risk_score: int | None
    reason: str | None
    intelligence_status: str

class IPIntelligence(BaseModel):
    id: int
    ip: str
    ip_version: int | None
    is_private: bool
    is_public: bool
    is_reserved: bool
    is_loopback: bool
    is_link_local: bool
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
    reputation: str | None
    risk_score: int | None
    classification: str
    reason: str | None

class IntelligenceResponse(BaseModel):
    email_id: int
    urls: list[URLIntelligence]
    domains: list[DomainIntelligence]
    ips: list[IPIntelligence]
