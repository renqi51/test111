from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ExtractedEvidence(BaseModel):
    source_file: str = Field(description="Input source file name.")
    chunk_index: int = Field(description="Zero-based chunk index in source file.")
    quote: str = Field(default="", description="Short evidence quote from the chunk text.")


class ExtractedNode(BaseModel):
    id: str = Field(min_length=1, description="Stable business identifier (not random UUID).")
    label: str = Field(min_length=1, description="Human-readable node label.")
    type: str = Field(min_length=1, description="Node type, e.g. Service / Protocol / StandardDoc.")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional extracted node attributes.",
    )
    evidence: list[ExtractedEvidence] = Field(
        default_factory=list,
        description="Evidence list for traceability.",
    )


class ExtractedEdge(BaseModel):
    source: str = Field(min_length=1, description="Source node id.")
    target: str = Field(min_length=1, description="Target node id.")
    interaction: str = Field(min_length=1, description="Relation type, e.g. USES / DEFINED_IN.")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional extracted edge attributes.",
    )
    evidence: list[ExtractedEvidence] = Field(
        default_factory=list,
        description="Evidence list for traceability.",
    )


class ExtractionResult(BaseModel):
    """Structured extraction payload from one chunk."""

    nodes: list[ExtractedNode] = Field(default_factory=list)
    edges: list[ExtractedEdge] = Field(default_factory=list)


class LocalImportRequest(BaseModel):
    dry_run: bool = Field(default=False, description="Run extraction only without writing to graph.")
    max_files: int | None = Field(
        default=None,
        ge=1,
        description="Optional maximum number of input files for debugging.",
    )
    only_extensions: list[str] | None = Field(
        default=None,
        description=(
            "If set, only ingest files with these suffixes (e.g. [\".yaml\", \".txt\"]). "
            "Use after a full PDF/MD run to add text/YAML without re-parsing PDFs."
        ),
    )


class LocalImportResponse(BaseModel):
    files_processed: int = Field(description="Number of input files processed successfully.")
    files_failed: int = Field(description="Number of files failed to parse or process.")
    chunks_processed: int = Field(description="Number of chunks sent to extraction.")
    nodes_extracted_raw: int = Field(description="Raw extracted node count before dedup.")
    edges_extracted_raw: int = Field(description="Raw extracted edge count before dedup.")
    nodes_merged: int = Field(description="Node count after normalization and dedup.")
    edges_merged: int = Field(description="Edge count after normalization and dedup.")
    dry_run: bool = Field(description="Whether graph write was skipped.")
    failed_files: list[str] = Field(default_factory=list, description="Failed file records.")
    notes: list[str] = Field(default_factory=list, description="Runtime notes and warnings.")
