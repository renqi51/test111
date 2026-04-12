from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class ExposureGenerateRequest(BaseModel):
    """Outside-in exposure: real crawl roots / IPs / CIDR materialization — no graph-invented FQDNs."""

    service: str = Field(description="VoWiFi | IMS | Open Gateway (attack scenario label)")
    domains: list[str] = Field(default_factory=list, description="Primary hostnames / roots from crawl or CT logs")
    ips: list[str] = Field(default_factory=list, description="Literal IPs in authorized scope")
    cidrs: list[str] = Field(default_factory=list, description="RFC1918 or lab CIDRs; expanded to hosts up to configured cap")
    mcc: str = Field(default="000", min_length=3, max_length=3, pattern=r"^\d{3}$", description="Reporting / tenant label only")
    mnc: str = Field(default="00", min_length=2, max_length=3, pattern=r"^\d{2,3}$", description="Reporting / tenant label only")
    include_probe: bool = Field(default=True, description="When true, run live probe before emitting rows")

    @model_validator(mode="after")
    def _require_real_assets(self) -> ExposureGenerateRequest:
        dom = [x.strip() for x in self.domains if x and str(x).strip()]
        ip = [x.strip() for x in self.ips if x and str(x).strip()]
        cidr = [x.strip() for x in self.cidrs if x and str(x).strip()]
        if not dom and not ip and not cidr:
            raise ValueError("outside_in_requires_assets: set at least one of domains, ips, cidrs")
        return self


class ExposureRow(BaseModel):
    candidate_fqdn: str
    protocol_stack: list[str]
    network_functions: list[str]
    evidence_docs: list[str]
    risk_hypotheses: list[str]
    confidence: float


class ExposureAnalyzeRequest(ExposureGenerateRequest):
    extra_hosts: list[str] = Field(default_factory=list, description="Additional hostnames merged into domain set")
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
    techniques: list[str] = Field(
        default_factory=list,
        description="GraphRAG+LLM 给出的授权测试动作序列。",
    )
    threat_vectors: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    graph_rag_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    graph_rag_analyst_notes: list[str] = Field(default_factory=list)


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
