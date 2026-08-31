from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, require_roles
from app.database.database import get_db
from app.database.models import Analysis, Email, GraphEdge, GraphNode, User
from app.services.graph_service import build_and_persist_graph

router = APIRouter(prefix="/api/v1/investigations", tags=["Graph"])


async def owned_analysis(db: AsyncSession, analysis_id: int, user: User) -> Analysis | None:
    return await db.scalar(
        select(Analysis)
        .join(Email, Email.id == Analysis.email_id)
        .where(Analysis.id == analysis_id, Email.user_id == user.id)
    )


async def read_graph(db: AsyncSession, analysis_id: int) -> dict[str, list[dict]]:
    nodes = list((await db.scalars(select(GraphNode).where(GraphNode.analysis_id == analysis_id).order_by(GraphNode.id))).all())
    node_map = {n.id: n for n in nodes}
    edges = list((await db.scalars(select(GraphEdge).where(GraphEdge.analysis_id == analysis_id).order_by(GraphEdge.id))).all())
    return {
        "nodes": [
            {"id": f"{n.node_type}:{n.node_value}", "label": n.node_value, "type": n.node_type, "metadata": n.metadata_json or {}}
            for n in nodes
        ],
        "edges": [
            {
                "source": f"{node_map[e.source_node_id].node_type}:{node_map[e.source_node_id].node_value}",
                "target": f"{node_map[e.target_node_id].node_type}:{node_map[e.target_node_id].node_value}",
                "relationship": e.relationship_type,
                "metadata": e.metadata_json or {},
            }
            for e in edges if e.source_node_id in node_map and e.target_node_id in node_map
        ],
    }


@router.get("/{analysis_id}/graph")
async def get_graph(
    analysis_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    analysis = await owned_analysis(db, analysis_id, user)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    graph = await read_graph(db, analysis_id)
    if not graph["nodes"]:
        try:
            graph = await build_and_persist_graph(db, analysis_id)
            await db.commit()
        except Exception:
            await db.rollback()
            raise HTTPException(status_code=500, detail="Unable to generate investigation graph")
    return graph


@router.post("/{analysis_id}/graph/rebuild")
async def rebuild_graph(
    analysis_id: int,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    analysis = await owned_analysis(db, analysis_id, user)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    try:
        graph = await build_and_persist_graph(db, analysis_id)
        await db.commit()
        return graph
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Unable to rebuild investigation graph") from exc
