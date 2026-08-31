from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Analysis, Domain, Email, GraphEdge, GraphNode, IPAddress, URL


@dataclass(frozen=True)
class GraphNodeData:
    node_type: str
    node_value: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdgeData:
    source: tuple[str, str]
    target: tuple[str, str]
    relationship: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphData:
    nodes: list[GraphNodeData] = field(default_factory=list)
    edges: list[GraphEdgeData] = field(default_factory=list)


def _add_node(graph: GraphData, seen: set[tuple[str, str]], node_type: str, value: str | None, **metadata: Any) -> None:
    if not value:
        return
    value = value.strip()
    if not value:
        return
    key = (node_type, value)
    if key not in seen:
        seen.add(key)
        graph.nodes.append(GraphNodeData(node_type, value, metadata))


def _add_edge(graph: GraphData, seen: set[tuple[tuple[str, str], tuple[str, str], str]], source: tuple[str, str], target: tuple[str, str], relationship: str, **metadata: Any) -> None:
    key = (source, target, relationship)
    if key not in seen and source != target:
        seen.add(key)
        graph.edges.append(GraphEdgeData(source, target, relationship, metadata))


def _email_sender_address(sender: str | None) -> str | None:
    if not sender:
        return None
    from email.utils import parseaddr
    _, address = parseaddr(sender)
    return address or sender.strip()


def _sender_domain(sender: str | None) -> str | None:
    address = _email_sender_address(sender)
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().strip().rstrip(".")


def build_graph(email: Email, urls: list[URL], domains: list[Domain], ips: list[IPAddress], hops: list[Any] | None = None) -> GraphData:
    """Build a deterministic relationship graph from observed email evidence."""
    graph = GraphData()
    node_seen: set[tuple[str, str]] = set()
    edge_seen: set[tuple[tuple[str, str], tuple[str, str], str]] = set()

    email_key = ("email", str(email.id))
    _add_node(graph, node_seen, "email", str(email.id), subject=email.subject or "")

    sender = _email_sender_address(email.sender)
    sender_domain = _sender_domain(email.sender)
    if sender:
        sender_key = ("sender", sender)
        _add_node(graph, node_seen, "sender", sender)
        _add_edge(graph, edge_seen, email_key, sender_key, "SENT_FROM")
    if sender_domain:
        domain_key = ("domain", sender_domain)
        _add_node(graph, node_seen, "domain", sender_domain, source="sender")
        _add_edge(graph, edge_seen, email_key, domain_key, "USES_DOMAIN")
        if sender:
            _add_edge(graph, edge_seen, sender_key, domain_key, "USES_DOMAIN")

    domain_keys: dict[str, tuple[str, str]] = {}
    for d in domains:
        if not d.domain:
            continue
        key = ("domain", d.domain.lower().rstrip("."))
        domain_keys[d.domain.lower().rstrip(".")] = key
        _add_node(graph, node_seen, "domain", key[1], is_lookalike=d.is_lookalike, is_suspicious=d.is_suspicious, risk_score=d.risk_score)
        _add_edge(graph, edge_seen, email_key, key, "RELATED_TO")

    for u in urls:
        value = u.normalized_url or u.url
        if not value:
            continue
        url_key = ("url", value)
        _add_node(graph, node_seen, "url", value, domain=u.domain, suspicious=u.is_suspicious, risk_score=u.risk_score)
        _add_edge(graph, edge_seen, email_key, url_key, "CONTAINS_URL")
        if u.domain:
            dkey = domain_keys.get(u.domain.lower().rstrip(".")) or ("domain", u.domain.lower().rstrip("."))
            _add_node(graph, node_seen, "domain", dkey[1])
            _add_edge(graph, edge_seen, url_key, dkey, "USES_DOMAIN")

    for ip in ips:
        ip_key = ("ip", ip.ip)
        _add_node(graph, node_seen, "ip", ip.ip, private=ip.is_private, asn=ip.asn, organization=ip.organization)
        _add_edge(graph, edge_seen, email_key, ip_key, "RELATED_TO")
        if ip.asn:
            asn_key = ("asn", ip.asn)
            _add_node(graph, node_seen, "asn", ip.asn)
            _add_edge(graph, edge_seen, ip_key, asn_key, "RELATED_TO")
        if ip.organization:
            org_key = ("organization", ip.organization)
            _add_node(graph, node_seen, "organization", ip.organization)
            _add_edge(graph, edge_seen, ip_key, org_key, "HOSTED_BY")

    for hop in sorted(hops or [], key=lambda h: getattr(h, "hop_order", 0)):
        if getattr(hop, "source_hostname", None):
            host_key = ("hostname", hop.source_hostname)
            _add_node(graph, node_seen, "hostname", hop.source_hostname)
            _add_edge(graph, edge_seen, email_key, host_key, "ROUTED_THROUGH", hop=hop.hop_order, reliable=hop.is_reliable)
        if getattr(hop, "source_ip", None):
            ip_key = ("ip", hop.source_ip)
            _add_node(graph, node_seen, "ip", hop.source_ip, private=hop.is_private_ip)
            _add_edge(graph, edge_seen, email_key, ip_key, "ROUTED_THROUGH", hop=hop.hop_order, reliable=hop.is_reliable)

    return graph


def serialize_graph(graph: GraphData) -> dict[str, list[dict[str, Any]]]:
    return {
        "nodes": [
            {"id": f"{n.node_type}:{n.node_value}", "label": n.node_value, "type": n.node_type, "metadata": n.metadata}
            for n in graph.nodes
        ],
        "edges": [
            {
                "source": f"{e.source[0]}:{e.source[1]}",
                "target": f"{e.target[0]}:{e.target[1]}",
                "relationship": e.relationship,
                "metadata": e.metadata,
            }
            for e in graph.edges
        ],
    }


async def persist_graph(db: AsyncSession, analysis_id: int, graph: GraphData) -> dict[str, list[dict[str, Any]]]:
    """Replace graph records atomically within the caller's transaction."""
    await db.execute(delete(GraphEdge).where(GraphEdge.analysis_id == analysis_id))
    await db.execute(delete(GraphNode).where(GraphNode.analysis_id == analysis_id))
    await db.flush()

    node_ids: dict[tuple[str, str], int] = {}
    for node in graph.nodes:
        row = GraphNode(analysis_id=analysis_id, node_type=node.node_type, node_value=node.node_value, metadata_json=node.metadata)
        db.add(row)
        await db.flush()
        node_ids[(node.node_type, node.node_value)] = row.id

    for edge in graph.edges:
        source_id = node_ids.get(edge.source)
        target_id = node_ids.get(edge.target)
        if source_id is None or target_id is None:
            continue
        db.add(GraphEdge(
            analysis_id=analysis_id,
            source_node_id=source_id,
            target_node_id=target_id,
            relationship_type=edge.relationship,
            metadata_json=edge.metadata,
        ))
    await db.flush()
    return serialize_graph(graph)


async def build_and_persist_graph(db: AsyncSession, analysis_id: int) -> dict[str, list[dict[str, Any]]]:
    """Load an analysis and its email evidence, build its graph, and persist it."""
    stmt = select(Analysis).where(Analysis.id == analysis_id).options()
    analysis = await db.scalar(stmt)
    if analysis is None:
        raise ValueError("Analysis not found")
    email = await db.scalar(select(Email).where(Email.id == analysis.email_id))
    if email is None:
        raise ValueError("Email not found")
    urls = list((await db.scalars(select(URL).where(URL.email_id == email.id))).all())
    domains = list((await db.scalars(select(Domain).where(Domain.email_id == email.id))).all())
    ips = list((await db.scalars(select(IPAddress).where(IPAddress.email_id == email.id))).all())
    # Import locally to keep graph service dependency-light.
    from app.database.models import ReceivedHop
    hops = list((await db.scalars(select(ReceivedHop).where(ReceivedHop.email_id == email.id))).all())
    graph = build_graph(email, urls, domains, ips, hops)
    return await persist_graph(db, analysis_id, graph)
