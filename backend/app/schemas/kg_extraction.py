from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ExtractedNode(BaseModel):
    id: str = Field(min_length=1, description="Stable business identifier for node normalization.")
    label: str = Field(min_length=1, description="Human-readable node label.")
    type: str = Field(min_length=1, description="Node type, e.g. Service/NetworkFunction/Protocol.")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary node attributes extracted from evidence-backed text.",
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence items. Each should contain source_file, chunk_index, quote.",
    )


class ExtractedEdge(BaseModel):
    source: str = Field(min_length=1, description="Source node id.")
    target: str = Field(min_length=1, description="Target node id.")
    interaction: str = Field(min_length=1, description="Relation type, e.g. documented_in / uses_protocol.")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary relation attributes extracted from text.",
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence items. Each should contain source_file, chunk_index, quote.",
    )


class ExtractionResult(BaseModel):
    nodes: list[ExtractedNode] = Field(default_factory=list)
    edges: list[ExtractedEdge] = Field(default_factory=list)
