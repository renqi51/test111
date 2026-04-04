from typing import Any
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    description: str = ""
    evidence_source: str = ""
    en_identifier: str = ""


class GraphEdge(BaseModel):
    source: str
    target: str
    interaction: str


class GraphPayload(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class GraphStats(BaseModel):
    node_count: int
    edge_count: int
    by_node_type: dict[str, int]
    by_edge_type: dict[str, int]
    top_degree_nodes: list[dict[str, Any]]


class ValidateIssue(BaseModel):
    code: str
    detail: str


class ValidateResult(BaseModel):
    ok: bool
    orphan_nodes: list[str]
    dangling_edges: list[dict[str, str]]
    unreferenced_standard_docs: list[str]
    risks_without_mitigation: list[str]
    node_type_counts: dict[str, int]
    edge_type_counts: dict[str, int]
    top_degree_nodes: list[dict[str, Any]]
    issues: list[ValidateIssue]
