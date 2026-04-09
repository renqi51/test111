from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ExposureGenerateRequest(BaseModel):
    service: str = Field(description="VoWiFi | IMS | Open Gateway")
    mcc: str = Field(min_length=3, max_length=3, pattern=r"^\d{3}$")
    mnc: str = Field(min_length=2, max_length=3, pattern=r"^\d{2,3}$")


class ExposureRow(BaseModel):
    candidate_fqdn: str
    protocol_stack: list[str]
    network_functions: list[str]
    evidence_docs: list[str]
    risk_hypotheses: list[str]
    confidence: float


class ExposureAnalyzeRequest(ExposureGenerateRequest):
    include_probe: bool = True
    extra_hosts: list[str] = Field(default_factory=list)
    use_llm: bool = True


class ExposurePattern(BaseModel):
    pattern_id: str
    service: str
    category: Literal["fqdn", "interface", "platform", "route"]
    expression: str
    rationale: str = ""
    evidence_docs: list[str] = Field(default_factory=list)


class CandidateEvidenceBundle(BaseModel):
    evidence_docs: list[str] = Field(default_factory=list)
    graph_paths: list[str] = Field(default_factory=list)
    related_risks: list[str] = Field(default_factory=list)
    source_kind: list[Literal["standard_pattern", "graph_inference", "probe_observation", "manual"]] = Field(
        default_factory=list
    )


class ExposureCandidate(BaseModel):
    candidate_id: str
    candidate_fqdn: str
    service: str
    protocols: list[str] = Field(default_factory=list)
    network_functions: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: CandidateEvidenceBundle
    probe_status: dict = Field(default_factory=dict)


class ExposureAssessment(BaseModel):
    candidate_id: str
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: str = ""
    conservative_explanation: str = ""
    attack_surface_notes: list[str] = Field(default_factory=list)
    attack_points: list[str] = Field(
        default_factory=list,
        description="High-level vulnerability hypotheses / worthwhile breakpoints (not exploit steps).",
    )
    validation_tasks: list[str] = Field(
        default_factory=list,
        description="Next checks to run in an authorized test environment (not attack scripts).",
    )
    missing_evidence: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    model_name: str = "deterministic"
    fallback_used: bool = False


class AttackPath(BaseModel):
    path_id: str
    candidate_id: str
    entrypoint: str
    pivots: list[str] = Field(default_factory=list)
    target_asset: str = ""
    likelihood: float = Field(default=0.0, ge=0.0, le=1.0)
    impact: Literal["low", "medium", "high"] = "low"
    prerequisites: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    validation_status: Literal["hypothesis", "partially_validated", "validated"] = "hypothesis"


class ExposureAnalysisResponse(BaseModel):
    run_id: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    service: str
    mcc: str
    mnc: str
    patterns: list[ExposurePattern] = Field(default_factory=list)
    candidates: list[ExposureCandidate] = Field(default_factory=list)
    assessments: list[ExposureAssessment] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    probe_run: dict | None = None
    report_path: str = ""
    summary: dict = Field(default_factory=dict)
