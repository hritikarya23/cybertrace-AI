from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rebrand.ly", "rb.gy"}
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "gq", "tk", "ml", "ga", "cf"}
CREDENTIAL_TERMS = {"login", "signin", "verify", "verification", "password", "credential", "account", "secure", "authenticate", "wallet"}
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+")

@dataclass(frozen=True)
class URLAnalysis:
    url: str
    normalized_url: str
    domain: str | None
    scheme: str | None
    port: int | None
    path: str | None
    is_shortened: bool
    is_suspicious: bool
    risk_score: int
    classification: str
    reason: str | None


def extract_urls(text: str | None) -> list[str]:
    if not text:
        return []
    found = []
    for raw in _URL_RE.findall(text):
        found.append(raw.rstrip(".,;:!?)]}"))
    return list(dict.fromkeys(found))


def normalize_url(raw: str) -> str:
    p = urlsplit(raw.strip())
    host = (p.hostname or "").lower().rstrip(".")
    scheme = p.scheme.lower()
    try:
        port = p.port
    except ValueError:
        port = None
    netloc = host
    if p.username is not None:
        netloc = f"{p.username}@{host}"
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, p.path or "/", p.query, p.fragment))


def analyze_url(raw: str) -> URLAnalysis:
    normalized = normalize_url(raw)
    p = urlsplit(normalized)
    host = (p.hostname or "").lower().rstrip(".") or None
    scheme = p.scheme.lower() or None
    reasons: list[str] = []
    risk = 0
    is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            is_ip = True
            risk += 25
            reasons.append("URL uses an IP address instead of a domain")
        except ValueError:
            pass
    shortened = bool(host and host in SHORTENERS)
    if shortened:
        risk += 15
        reasons.append("URL uses a known shortening service")
    if host and host.startswith("xn--"):
        risk += 20
        reasons.append("Punycode hostname detected")
    labels = host.split(".") if host else []
    if len(labels) > 4:
        risk += 10
        reasons.append("Excessive subdomain depth")
    tld = labels[-1] if len(labels) >= 2 else ""
    if tld in SUSPICIOUS_TLDS:
        risk += 10
        reasons.append("Hostname uses a potentially high-risk TLD")
    path_lower = unquote(p.path or "").lower()
    if any(term in path_lower for term in CREDENTIAL_TERMS):
        risk += 15
        reasons.append("Credential or account-related path detected")
    if "%" in raw or (p.query and len(p.query) > 120):
        risk += 10
        reasons.append("Encoded or unusually complex URL detected")
    if p.port and p.port not in {80, 443}:
        risk += 15
        reasons.append("Unusual destination port")
    if "@" in raw.split("//", 1)[-1].split("/", 1)[0]:
        risk += 15
        reasons.append("Userinfo component may obscure the destination host")
    risk = min(risk, 100)
    suspicious = risk >= 20
    classification = "suspicious" if suspicious else "normal"
    return URLAnalysis(raw, normalized, host, scheme, p.port, p.path or "/", shortened, suspicious, risk, classification, "; ".join(reasons) if reasons else None)
