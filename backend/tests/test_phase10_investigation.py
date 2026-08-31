import pytest
from unittest.mock import AsyncMock, patch

from app.services.investigation_service import _evidence_from_forensics
from app.services.header_analyzer import AuthenticationFinding, HeaderForensicsResult


def test_forensic_evidence_is_mapped_to_risk_categories():
    result = HeaderForensicsResult(
        from_address="a@example.com", reply_to="b@evil.test", return_path="c@evil.test", message_id="<x@example.com>",
        from_reply_to_mismatch=True, from_return_path_mismatch=True, message_id_domain="example.com", from_domain="example.com",
        message_id_domain_consistent=True, authentication=AuthenticationFinding(spf_result="fail", dkim_result="pass", dmarc_result="fail"),
        routing_hops=[], earliest_reliable_sending_node=None, dkim_signatures=[], findings=[]
    )
    evidence = _evidence_from_forensics(result)
    assert {x.category for x in evidence} == {"authentication_header"}
    assert len(evidence) == 4


def test_phase10_module_imports():
    from app.api.routes.analysis import router
    assert any(getattr(r, "path", "") == "/api/v1/analysis" for r in router.routes)
