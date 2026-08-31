from __future__ import annotations

import ipaddress
from dataclasses import dataclass

@dataclass(frozen=True)
class IPAnalysis:
    ip: str
    ip_version: int
    is_private: bool
    is_public: bool
    is_reserved: bool
    is_loopback: bool
    is_link_local: bool
    risk_score: int
    classification: str
    reason: str | None


def analyze_ip(value: str) -> IPAnalysis:
    address = ipaddress.ip_address(value)
    reasons: list[str] = []
    risk = 0
    if address.is_private:
        reasons.append("Private IP; public geolocation should not be attempted")
    if address.is_reserved:
        risk += 20
        reasons.append("Reserved IP range")
    if address.is_loopback:
        risk += 20
        reasons.append("Loopback address")
    if address.is_link_local:
        risk += 10
        reasons.append("Link-local address")
    public = address.is_global
    classification = "public" if public else "non_public"
    return IPAnalysis(str(address), address.version, address.is_private, public, address.is_reserved, address.is_loopback, address.is_link_local, min(risk, 100), classification, "; ".join(reasons) if reasons else None)
