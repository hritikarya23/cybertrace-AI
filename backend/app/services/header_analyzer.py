from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime


@dataclass(slots=True)
class AuthenticationFinding:
    spf_result: str = "unknown"
    dkim_result: str = "unknown"
    dmarc_result: str = "unknown"
    spf_domain: str | None = None
    dkim_domain: str | None = None
    dmarc_policy: str | None = None
    raw_authentication_header: str | None = None


@dataclass(slots=True)
class ReceivedHopFinding:
    hop_order: int
    raw_received_header: str
    source_ip: str | None
    source_hostname: str | None
    destination_hostname: str | None
    timestamp: datetime | None
    is_private_ip: bool
    is_public_ip: bool
    is_reliable: bool


@dataclass(slots=True)
class HeaderForensicsResult:
    from_address: str | None
    reply_to: str | None
    return_path: str | None
    message_id: str | None
    from_reply_to_mismatch: bool
    from_return_path_mismatch: bool
    message_id_domain: str | None
    from_domain: str | None
    message_id_domain_consistent: bool | None
    authentication: AuthenticationFinding
    routing_hops: list[ReceivedHopFinding]
    earliest_reliable_sending_node: ReceivedHopFinding | None
    dkim_signatures: list[dict[str, str | None]]
    findings: list[str]


IP_RE = re.compile(
    r"(?<![\w:.])(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})(?![\w:.])"
)
HOST_RE = re.compile(r"\b(?:from|by)\s+([^\s(]+)", re.I)
FROM_IP_RE = re.compile(r"\bfrom\s+[^\s(]+\s+\((?:[^\[]+\s+)?\[([^\]]+)\]", re.I)
BRACKET_IP_RE = re.compile(r"\[([^\]]+)\]")
AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
DKIM_FIELD_RE = re.compile(r"(?:^|;)\s*([a-zA-Z]+)=([^;]+)")

KNOWN_AUTH_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown"}


def _domain(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"@([^\s>]+)", value)
    return match.group(1).rstrip(".").lower() if match else None


def _message_id_domain(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"@([^>\s]+)", value)
    return match.group(1).rstrip(".").lower() if match else None


def _same_or_subdomain(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _parse_timestamp(header: str) -> datetime | None:
    # RFC Received headers conventionally end in a semicolon followed by date.
    if ";" not in header:
        return None
    value = header.rsplit(";", 1)[1].strip()
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _extract_ip(header: str) -> str | None:
    candidates = BRACKET_IP_RE.findall(header)
    candidates += IP_RE.findall(header)
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def _extract_host(header: str, keyword: str) -> str | None:
    match = re.search(rf"\b{keyword}\s+([^\s(]+)", header, re.I)
    return match.group(1).rstrip(".") if match else None


def _authentication(headers: list[str]) -> AuthenticationFinding:
    result = AuthenticationFinding()
    if not headers:
        return result
    result.raw_authentication_header = headers[0]

    # Authentication-Results may appear more than once. Use the first explicit
    # result for each mechanism, preserving unknown when a mechanism is absent.
    for header in headers:
        for mechanism, value in AUTH_RESULT_RE.findall(header):
            mechanism = mechanism.lower()
            value = value.lower()
            if value not in KNOWN_AUTH_RESULTS:
                value = "unknown"
            if mechanism == "spf" and result.spf_result == "unknown":
                result.spf_result = value
            elif mechanism == "dkim" and result.dkim_result == "unknown":
                result.dkim_result = value
            elif mechanism == "dmarc" and result.dmarc_result == "unknown":
                result.dmarc_result = value

        lower = header.lower()
        smtp_match = re.search(r"(?:smtp\.mailfrom|envelope-from)=\s*([^;\s]+)", lower)
        if smtp_match and not result.spf_domain:
            result.spf_domain = _domain(smtp_match.group(1)) or smtp_match.group(1).strip("<>")
        dkim_from = re.search(r"(?:header\.d)=\s*([^;\s]+)", lower)
        if dkim_from and not result.dkim_domain:
            result.dkim_domain = dkim_from.group(1).strip("<>").rstrip(".").lower()
        header_from = re.search(r"(?:header\.from)=\s*([^;\s]+)", lower)
        if header_from and not result.dmarc_policy:
            result.dmarc_policy = None
            result.dmarc_policy = "unknown"
            # Keep only the policy if explicitly present below.
        policy_match = re.search(r"\bp=\s*([a-z]+)", lower)
        if policy_match and result.dmarc_policy in {None, "unknown"}:
            result.dmarc_policy = policy_match.group(1)

    return result


def _parse_dkim_signatures(headers: list[str]) -> list[dict[str, str | None]]:
    parsed: list[dict[str, str | None]] = []
    for header in headers:
        fields: dict[str, str | None] = {}
        for key, value in DKIM_FIELD_RE.findall(header):
            fields[key.lower()] = value.strip()
        parsed.append({"d": fields.get("d"), "s": fields.get("s")})
    return parsed


def _parse_received(headers: list[str]) -> list[ReceivedHopFinding]:
    hops: list[ReceivedHopFinding] = []
    # Message headers are stored newest-first. For routing visualization, hop 1
    # is the earliest hop represented by the header set (reverse chronological).
    for order, header in enumerate(reversed(headers), start=1):
        source_ip = _extract_ip(header)
        try:
            address = ipaddress.ip_address(source_ip) if source_ip else None
        except ValueError:
            address = None
        private = bool(address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved))
        public = bool(address and address.is_global)
        # Reliability is intentionally conservative: a public source IP plus a
        # syntactically parseable Received line is considered reliable enough for
        # "earliest reliable" infrastructure tracing, not attacker attribution.
        reliable = bool(source_ip and public)
        hops.append(
            ReceivedHopFinding(
                hop_order=order,
                raw_received_header=header,
                source_ip=source_ip,
                source_hostname=_extract_host(header, "from"),
                destination_hostname=_extract_host(header, "by"),
                timestamp=_parse_timestamp(header),
                is_private_ip=private,
                is_public_ip=public,
                is_reliable=reliable,
            )
        )
    return hops


def analyze_headers(raw_email: bytes | str) -> HeaderForensicsResult:
    """Perform passive header forensics; no DNS, URL fetching, or cryptographic DKIM verification."""
    raw = raw_email.encode("utf-8", errors="replace") if isinstance(raw_email, str) else raw_email
    message = BytesParser(policy=policy.default).parsebytes(raw)
    from_value = str(message.get("From")) if message.get("From") is not None else None
    reply_to = str(message.get("Reply-To")) if message.get("Reply-To") is not None else None
    return_path = str(message.get("Return-Path")) if message.get("Return-Path") is not None else None
    message_id = str(message.get("Message-ID")) if message.get("Message-ID") is not None else None
    received = [str(v) for v in message.get_all("Received", [])]
    auth_headers = [str(v) for v in message.get_all("Authentication-Results", [])]
    dkim_headers = [str(v) for v in message.get_all("DKIM-Signature", [])]

    from_domain = _domain(from_value)
    reply_domain = _domain(reply_to)
    return_domain = _domain(return_path)
    msg_domain = _message_id_domain(message_id)

    findings: list[str] = []
    from_reply_mismatch = bool(from_domain and reply_domain and from_domain != reply_domain)
    from_return_mismatch = bool(from_domain and return_domain and from_domain != return_domain)
    msg_consistent = None if not msg_domain or not from_domain else _same_or_subdomain(msg_domain, from_domain)

    if from_reply_mismatch:
        findings.append("From and Reply-To domains differ")
    if from_return_mismatch:
        findings.append("From and Return-Path domains differ")
    if msg_consistent is False:
        findings.append("Message-ID domain is inconsistent with the From domain")

    auth = _authentication(auth_headers)
    if auth.spf_result == "fail":
        findings.append("SPF authentication failed")
    if auth.dkim_result == "fail":
        findings.append("DKIM authentication reported failure; cryptographic verification was not performed")
    if auth.dmarc_result == "fail":
        findings.append("DMARC authentication failed")

    hops = _parse_received(received)
    earliest = next((hop for hop in hops if hop.is_reliable), None)
    if earliest:
        findings.append("Earliest reliable sending node is an estimated infrastructure origin, not an attacker identity")
    elif hops:
        findings.append("No public IP was reliable enough to identify an earliest sending node")

    return HeaderForensicsResult(
        from_address=from_value,
        reply_to=reply_to,
        return_path=return_path,
        message_id=message_id,
        from_reply_to_mismatch=from_reply_mismatch,
        from_return_path_mismatch=from_return_mismatch,
        message_id_domain=msg_domain,
        from_domain=from_domain,
        message_id_domain_consistent=msg_consistent,
        authentication=auth,
        routing_hops=hops,
        earliest_reliable_sending_node=earliest,
        dkim_signatures=_parse_dkim_signatures(dkim_headers),
        findings=findings,
    )
