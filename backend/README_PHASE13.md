# SIH26106 — Phase 13: Graph Analysis

Phase 13 adds the PostgreSQL-backed relationship graph service. It uses the existing `graph_nodes` and `graph_edges` tables; Neo4j is not required for the MVP.

## Implemented
- Deterministic graph generation from email, sender/domain, URLs, IPs, routing hops, ASN and organization evidence.
- Relationship types: `SENT_FROM`, `USES_DOMAIN`, `CONTAINS_URL`, `ROUTED_THROUGH`, `HOSTED_BY`, `RELATED_TO`.
- Stable frontend node IDs such as `domain:example.com` and `ip:203.0.113.10`.
- JSON metadata on nodes/edges.
- De-duplication of nodes and edges.
- Atomic graph replacement inside the caller transaction.
- Ownership checks through JWT.
- Viewer can read; analyst/admin can rebuild.
- `GET /api/v1/investigations/{id}/graph` lazily creates a graph if none exists.
- `POST /api/v1/investigations/{id}/graph/rebuild` explicitly regenerates it.

## API

```http
GET /api/v1/investigations/{id}/graph
POST /api/v1/investigations/{id}/graph/rebuild
```

Example response:

```json
{
  "nodes": [
    {"id": "email:123", "label": "123", "type": "email", "metadata": {}},
    {"id": "domain:example.com", "label": "example.com", "type": "domain", "metadata": {}}
  ],
  "edges": [
    {"source": "email:123", "target": "domain:example.com", "relationship": "USES_DOMAIN", "metadata": {}}
  ]
}
```

## Design note
The graph represents observed/inferred investigation relationships. It does not establish attacker identity. IP geolocation and infrastructure attribution remain estimates and must retain their uncertainty.
