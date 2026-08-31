from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict


class AuthenticationForensicsResponse(BaseModel):
    spf_result: str
    dkim_result: str
    dmarc_result: str
    spf_domain: str | None
    dkim_domain: str | None
    dmarc_policy: str | None
    raw_authentication_header: str | None


class ReceivedHopResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    hop_order: int
    raw_received_header: str
    source_ip: str | None
    source_hostname: str | None
    destination_hostname: str | None
    timestamp: datetime | None
    is_private_ip: bool
    is_public_ip: bool
    is_reliable: bool


class HeaderForensicsResponse(BaseModel):
    email_id: int
    from_address: str | None
    reply_to: str | None
    return_path: str | None
    message_id: str | None
    from_reply_to_mismatch: bool
    from_return_path_mismatch: bool
    message_id_domain: str | None
    from_domain: str | None
    message_id_domain_consistent: bool | None
    authentication: AuthenticationForensicsResponse
    routing_hops: list[ReceivedHopResponse]
    earliest_reliable_sending_node: ReceivedHopResponse | None
    dkim_signatures: list[dict[str, str | None]]
    findings: list[str]
    note: str
