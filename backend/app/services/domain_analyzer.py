from __future__ import annotations

import os
import re
from dataclasses import dataclass

@dataclass(frozen=True)
class DomainAnalysis:
    domain: str
    is_lookalike: bool
    target_brand: str | None
    confidence: float
    is_suspicious: bool
    risk_score: int
    reason: str | None
    intelligence_status: str = "unavailable"


def _brands() -> dict[str, str]:
    raw = os.getenv("TRUSTED_BRANDS", "")
    result: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":", 1)
        brand = parts[0].strip().lower()
        domain = parts[1].strip().lower() if len(parts) == 2 else brand
        result[brand] = domain
    return result


def _skeleton(value: str) -> str:
    value = value.lower().replace("xn--", "")
    return re.sub(r"[0-9@._-]", "", value).replace("0", "o").replace("1", "l")


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyze_domain(domain: str, sender_domain: str | None = None) -> DomainAnalysis:
    d = domain.strip().lower().rstrip(".")
    brands = _brands()
    reasons: list[str] = []
    risk = 0
    target = None
    confidence = 0.0
    if d.startswith("xn--") or ".xn--" in d:
        risk += 25
        reasons.append("Punycode domain detected")
    if sender_domain and d != sender_domain.lower().rstrip("."):
        # Caller may use this as context; mismatch alone is not automatically malicious.
        reasons.append("Domain differs from sender domain")
    for brand, trusted_domain in brands.items():
        base = trusted_domain.split(".")[0]
        dbase = d.split(".")[-2] if d.count(".") >= 1 else d
        if d == trusted_domain:
            continue
        distance = _edit_distance(_skeleton(dbase), _skeleton(base))
        if distance <= max(1, len(base) // 4) or _skeleton(dbase) == _skeleton(base):
            target = brand
            confidence = min(0.99, 0.70 + 0.08 * max(0, len(base) - distance))
            risk += 45
            reasons.append(f"Possible look-alike of trusted brand {brand}")
            break
    labels = d.split(".")
    if len(labels) > 4:
        risk += 10
        reasons.append("Deep subdomain structure")
    suspicious = risk >= 25
    return DomainAnalysis(d, target is not None, target, round(confidence, 2), suspicious, min(risk, 100), "; ".join(reasons) if reasons else None)
