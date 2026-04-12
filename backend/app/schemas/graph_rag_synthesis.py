from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AttackPathSynthesisRow(BaseModel):
    """LLM+GraphRAG 输出的单条攻击路径结构化结果（经图谱上下文约束）。"""

    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="模型对结构化路径的自评置信度。")
    pivots: list[str] = Field(default_factory=list)
    target_asset: str = ""
    likelihood: float = Field(default=0.5, ge=0.0, le=1.0)
    impact: Literal["low", "medium", "high"] = "medium"
    prerequisites: list[str] = Field(default_factory=list)
    validation_status: Literal["hypothesis", "partially_validated", "validated"] = "hypothesis"
    techniques: list[str] = Field(
        default_factory=list,
        description="可执行的红队验证步骤：须含具体工具参数、脚本名、端口、抓包过滤式或畸形包字段说明（仅授权靶场）。",
    )
    threat_vectors: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class AttackPathSynthesisBatch(BaseModel):
    paths: list[AttackPathSynthesisRow] = Field(default_factory=list)
    analyst_notes: list[str] = Field(default_factory=list)


class ExposureAssessmentSynthesis(BaseModel):
    """GraphRAG 侧输出的评估结构化结果，用于 LLM 主路径失败时的同源补强。"""

    risk_level: Literal["low", "medium", "high", "critical"] = "medium"
    score: float = Field(default=0.55, ge=0.0, le=1.0)
    summary: str = ""
    conservative_explanation: str = ""
    attack_surface_notes: list[str] = Field(default_factory=list)
    attack_points: list[str] = Field(default_factory=list)
    validation_tasks: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class ReActAgentDecision(BaseModel):
    """ReAct 单步：思考 + 工具选择 + 输入。"""

    thought: str = ""
    action: Literal["probe", "graph_rag", "synthesize", "finish"] = "finish"
    action_input: dict[str, str] = Field(default_factory=dict)
