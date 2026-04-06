from fastapi import APIRouter, Query

from app.schemas.graph import GraphEdge, GraphNode, GraphPayload, GraphStats, ValidateResult
from app.schemas.merge import MergeRequest, MergeResponse
from app.services.graph_engine import compute_stats, validate_graph
from app.repositories.graph_repository import get_graph_repository
from app.utils.storage import graph_from_csv_seed

router = APIRouter(tags=["graph"])


@router.get("/graph", response_model=GraphPayload)
def get_graph():
    repo = get_graph_repository()
    g = repo.get_graph()
    nodes = [GraphNode.model_validate(n) for n in g["nodes"]]
    edges = [GraphEdge.model_validate(e) for e in g["edges"]]
    return GraphPayload(nodes=nodes, edges=edges)


@router.get("/graph/stats", response_model=GraphStats)
def graph_stats():
    repo = get_graph_repository()
    g = repo.get_graph()
    s = compute_stats(g["nodes"], g["edges"])
    return GraphStats(
        node_count=s["node_count"],
        edge_count=s["edge_count"],
        by_node_type=s["by_node_type"],
        by_edge_type=s["by_edge_type"],
        top_degree_nodes=s["top_degree_nodes"],
    )


@router.post("/graph/validate", response_model=ValidateResult)
def graph_validate():
    repo = get_graph_repository()
    g = repo.get_graph()
    return validate_graph(g["nodes"], g["edges"])


@router.post("/graph/merge", response_model=MergeResponse)
def graph_merge(body: MergeRequest):
    repo = get_graph_repository()
    new_nodes = [m.model_dump() for m in body.nodes]
    new_edges = [m.model_dump() for m in body.edges]
    merged = repo.merge_nodes_edges(new_nodes, new_edges)
    # For response stats re-use graph_engine.merge_candidates logic on top of merged state
    # to compute how many would be newly added vs skipped, without persisting again.
    current = repo.get_graph()
    from app.services.graph_engine import merge_candidates as _merge_preview

    added_n, added_e, skip_n, skip_e, _, _ = _merge_preview(
        current["nodes"],
        current["edges"],
        new_nodes,
        new_edges,
    )
    return MergeResponse(
        added_nodes=added_n,
        added_edges=added_e,
        skipped_nodes=skip_n,
        skipped_edges=skip_e,
        graph=GraphPayload(
            nodes=[GraphNode.model_validate(n) for n in merged["nodes"]],
            edges=[GraphEdge.model_validate(e) for e in merged["edges"]],
        ),
    )


@router.get("/graph/node/{node_id}", response_model=GraphNode | None)
def graph_node(node_id: str):
    repo = get_graph_repository()
    n = repo.get_node(node_id)
    return GraphNode.model_validate(n) if n else None


@router.get("/graph/neighbors/{node_id}", response_model=GraphPayload)
def graph_neighbors(node_id: str, depth: int = 1):
    repo = get_graph_repository()
    sub = repo.neighbors(node_id, depth=depth)
    return GraphPayload(
        nodes=[GraphNode.model_validate(n) for n in sub["nodes"]],
        edges=[GraphEdge.model_validate(e) for e in sub["edges"]],
    )


@router.get("/graph/subgraph/search", response_model=GraphPayload)
def graph_subgraph_search(
    q: str = Query(min_length=1, description="关键词，按 id/label/description 匹配子图种子"),
    seed_limit: int = Query(default=20, ge=1, le=200),
    max_edges: int = Query(default=120, ge=1, le=3000),
):
    """
    按关键词返回子图，优先用于前端大图性能优化（避免一次渲染全图）。
    - Neo4j 后端：走数据库子图查询；
    - file 后端：走内存图过滤（兼容模式）。
    """
    repo = get_graph_repository()
    sub = repo.subgraph_for_graph_rag_question(
        q,
        seed_limit=seed_limit,
        max_edges=max_edges,
    )
    return GraphPayload(
        nodes=[GraphNode.model_validate(n) for n in sub["nodes"]],
        edges=[GraphEdge.model_validate(e) for e in sub["edges"]],
    )


@router.post("/graph/import/csv", response_model=GraphPayload)
def graph_import_csv():
    """
    从 backend/data/seed/nodes.csv / edges.csv 导入图谱到当前后端（包括 Neo4j）。
    可用于初始化或重置 Neo4j 图谱。
    """
    repo = get_graph_repository()
    seed_payload = graph_from_csv_seed()
    repo.save_graph({"nodes": seed_payload["nodes"], "edges": seed_payload["edges"]})
    g = repo.get_graph()
    return GraphPayload(
        nodes=[GraphNode.model_validate(n) for n in g["nodes"]],
        edges=[GraphEdge.model_validate(e) for e in g["edges"]],
    )


@router.get("/graph/export/json", response_model=GraphPayload)
def graph_export_json():
    """导出当前图谱（无论来自 Neo4j 还是文件后端）为 JSON。"""
    repo = get_graph_repository()
    g = repo.get_graph()
    return GraphPayload(
        nodes=[GraphNode.model_validate(n) for n in g["nodes"]],
        edges=[GraphEdge.model_validate(e) for e in g["edges"]],
    )
