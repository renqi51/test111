from pydantic import BaseModel
from .extract import CandidateNode, CandidateEdge
from .graph import GraphPayload


class MergeRequest(BaseModel):
    nodes: list[CandidateNode]
    edges: list[CandidateEdge]


class MergeResponse(BaseModel):
    added_nodes: int
    added_edges: int
    skipped_nodes: int
    skipped_edges: int
    graph: GraphPayload
