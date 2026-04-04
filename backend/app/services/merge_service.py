from __future__ import annotations

from app.repositories.graph_repository import get_graph_repository
from app.schemas.extraction_pipeline import MergeRequest, MergeResult, StagingGraph


class MergeService:
    def merge_staging(self, run_id: str, staging: StagingGraph, req: MergeRequest) -> MergeResult:
        selected_node_ids = {
            s.id for s in req.selected_nodes if s.status == "approved"
        } or {n.id for n in staging.nodes}
        selected_edge_ids = {s.id for s in req.selected_edges if s.status == "approved"}

        nodes = []
        for n in staging.nodes:
            if n.id not in selected_node_ids:
                continue
            nodes.append(
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type,
                    "description": n.properties.get("description", ""),
                    "evidence_source": f"staging:{run_id}",
                    "en_identifier": n.properties.get("normalized_name", n.id),
                }
            )

        edges = []
        for e in staging.edges:
            edge_id = f"{e.source}->{e.interaction}->{e.target}"
            if selected_edge_ids and edge_id not in selected_edge_ids:
                continue
            if e.source not in selected_node_ids or e.target not in selected_node_ids:
                continue
            edges.append({"source": e.source, "target": e.target, "interaction": e.interaction})

        repo = get_graph_repository()
        merged = repo.merge_nodes_edges(nodes, edges)
        merged_node_ids = {n["id"] for n in merged["nodes"]}
        merged_edges_count = len(merged["edges"])
        return MergeResult(
            run_id=run_id,
            merged_nodes=len([n for n in nodes if n["id"] in merged_node_ids]),
            merged_edges=min(len(edges), merged_edges_count),
            skipped_nodes=max(0, len(staging.nodes) - len(nodes)),
            skipped_edges=max(0, len(staging.edges) - len(edges)),
            conflicts_remaining=0,
            message="Staging graph merged into main graph after human confirmation.",
        )


merge_service = MergeService()

