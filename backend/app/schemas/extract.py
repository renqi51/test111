from pydantic import BaseModel, Field


class CandidateNode(BaseModel):
    id: str
    label: str
    type: str
    description: str = ""
    evidence_source: str = "规则抽取"
    en_identifier: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class CandidateEdge(BaseModel):
    source: str
    target: str
    interaction: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.75)


class ExtractRequest(BaseModel):
    text: str


class ExtractResponse(BaseModel):
    nodes: list[CandidateNode]
    edges: list[CandidateEdge]
    matched_patterns: list[str] = []


class LLMExtractNode(BaseModel):
    id: str
    label: str
    type: str
    description: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    source_span: str | None = None


class LLMExtractEdge(BaseModel):
    source: str
    target: str
    interaction: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str | None = None


class LLMRiskHypothesis(BaseModel):
    label: str
    description: str = ""
    confidence: float = Field(ge=0.0, le=1.0)


class LLMExtractPayload(BaseModel):
    nodes: list[LLMExtractNode] = []
    edges: list[LLMExtractEdge] = []
    risk_hypotheses: list[LLMRiskHypothesis] = []
    notes: list[str] = []


class HybridExtractResponse(BaseModel):
    rule: ExtractResponse
    llm: LLMExtractPayload | None
    merged: ExtractResponse
    provenance: dict[str, str]
