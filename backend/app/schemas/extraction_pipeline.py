from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

MergeStatus = Literal["pending", "approved", "rejected", "merged"]


class DocumentInput(BaseModel):
    document_id: str
    title: str = ""
    source_type: Literal["text", "upload", "path", "seeded", "manual"] = "text"
    raw_text: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DocumentChunk(BaseModel):
    chunk_id: str
    document_id: str
    section_id: str = ""
    heading: str = ""
    text: str
    order: int
    char_start: int = 0
    char_end: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    evidence_id: str
    chunk_id: str
    document_id: str
    heading: str = ""
    text: str
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    source_locator: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class EvidencePack(BaseModel):
    pack_id: str
    query: str
    document_id: str
    scenario_hint: str = ""
    items: list[EvidenceItem] = Field(default_factory=list)
    retrieval_strategy: str = "keyword_overlap"
    retrieval_version: str = "v1"
    rerank_used: bool = False
    rerank_strategy: str | None = None
    retriever_config: dict[str, Any] = Field(default_factory=dict)
    retrieval_trace: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class StateNodeCandidate(BaseModel):
    temp_id: str
    name: str
    normalized_name: str = ""
    description: str = ""
    state_type: str = "State"
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class TransitionCandidate(BaseModel):
    temp_id: str
    from_state: str
    to_state: str
    trigger: str = ""
    guard: str = ""
    action: str = ""
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class ExtractionResult(BaseModel):
    run_id: str
    worker_name: str
    extraction_mode: Literal["conservative", "structural", "repair"] = "conservative"
    states: list[StateNodeCandidate] = Field(default_factory=list)
    transitions: list[TransitionCandidate] = Field(default_factory=list)
    entities: list[dict[str, Any]] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    confidence_summary: dict[str, float] = Field(default_factory=dict)
    raw_response: dict[str, Any] = Field(default_factory=dict)
    evidence_pack_id: str = ""
    prompt_version: str = ""
    model_name: str = ""
    timing_ms: int = 0
    token_usage: dict[str, int] = Field(default_factory=dict)


class JudgeScoreDetail(BaseModel):
    worker_name: str
    schema_validity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_alignment_score: float = Field(default=0.0, ge=0.0, le=1.0)
    graph_consistency_score: float = Field(default=0.0, ge=0.0, le=1.0)
    completeness_score: float = Field(default=0.0, ge=0.0, le=1.0)
    conservativeness_score: float = Field(default=0.0, ge=0.0, le=1.0)
    total_score: float = Field(default=0.0, ge=0.0, le=1.0)
    comments: list[str] = Field(default_factory=list)


class ConflictItem(BaseModel):
    field_path: str
    conflict_type: str
    description: str
    candidate_values: dict[str, Any] = Field(default_factory=dict)
    related_evidence_ids: list[str] = Field(default_factory=list)
    severity: Literal["low", "medium", "high"] = "medium"


class JudgeDecision(BaseModel):
    judge_run_id: str
    score_details: list[JudgeScoreDetail] = Field(default_factory=list)
    recommended_worker: str = ""
    recommended_merge_strategy: str = "prefer_recommended_worker"
    conflict_set: list[ConflictItem] = Field(default_factory=list)
    needs_repair: bool = False
    repair_instruction: str = ""
    prompt_version: str = ""
    model_name: str = ""
    timing_ms: int = 0
    token_usage: dict[str, int] = Field(default_factory=dict)
    normalization_notes: list[str] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)
    retry_reason: str = ""
    fallback_reason: str = ""


class RepairedExtractionResult(BaseModel):
    run_id: str
    updated_fields: list[str] = Field(default_factory=list)
    extraction_result: ExtractionResult
    unresolved_conflicts: list[ConflictItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class StagingGraphNode(BaseModel):
    id: str
    label: str
    type: str
    properties: dict[str, Any] = Field(default_factory=dict)
    source_doc_id: str
    source_chunk_ids: list[str] = Field(default_factory=list)
    source_worker: str = ""
    judge_score: float = 0.0
    merge_status: MergeStatus = "pending"
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class StagingGraphEdge(BaseModel):
    source: str
    target: str
    interaction: str
    properties: dict[str, Any] = Field(default_factory=dict)
    source_doc_id: str
    source_chunk_ids: list[str] = Field(default_factory=list)
    source_worker: str = ""
    judge_score: float = 0.0
    merge_status: MergeStatus = "pending"
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class StagingGraph(BaseModel):
    run_id: str
    document_id: str
    nodes: list[StagingGraphNode] = Field(default_factory=list)
    edges: list[StagingGraphEdge] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MergeSelection(BaseModel):
    id: str
    status: Literal["approved", "rejected", "pending"] = "approved"
    normalized_to: str | None = None


class MergeRequest(BaseModel):
    selected_nodes: list[MergeSelection] = Field(default_factory=list)
    selected_edges: list[MergeSelection] = Field(default_factory=list)
    notes: str = ""


class MergeResult(BaseModel):
    run_id: str
    merged_nodes: int = 0
    merged_edges: int = 0
    skipped_nodes: int = 0
    skipped_edges: int = 0
    conflicts_remaining: int = 0
    message: str = ""


class ExperimentRecord(BaseModel):
    run_id: str
    input: DocumentInput
    evidence_pack: EvidencePack
    workers: list[ExtractionResult]
    judge: JudgeDecision
    repair: RepairedExtractionResult | None = None
    final_staging_graph: StagingGraph
    human_decision: MergeResult | None = None
    report_path: str = ""


class ExtractionRunRequest(BaseModel):
    text: str = ""
    title: str = ""
    source_type: Literal["text", "upload", "path", "seeded", "manual"] = "text"
    scenario_hint: str = "IMS"
    budget_mode: Literal["default", "high_precision"] = "default"
    high_precision: bool = False
    retrieval_strategy: Literal["keyword_overlap", "bm25", "vector"] | str | None = None
    rerank_used: bool | None = None
    rerank_strategy: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExtractionRunResponse(BaseModel):
    run_id: str
    stage: str
    evidence_pack: EvidencePack
    worker_results: list[ExtractionResult]
    judge: JudgeDecision
    repair: RepairedExtractionResult | None = None
    staging_graph_summary: dict[str, Any]
    trace_summary: dict[str, Any]
    run_meta: dict[str, Any] = Field(default_factory=dict)


class ExtractionStatusResponse(BaseModel):
    llm: dict[str, Any]
    retrieval: dict[str, Any]
    graph: dict[str, Any]
    budget: dict[str, Any]
    latest: dict[str, Any] | None = None
    latest_run_id: str | None = None

