from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PlaybookEvidenceItem(BaseModel):
    """单条「已执行验证」的可观测证据，用于对抗纯 LLM 幻觉。"""

    title: str = Field(default="", description="对应验证点标题，如 UDP500 IKE 版本探测")
    validation_status: Literal["Validated_Success", "Validated_Failed", "Skipped"] = "Skipped"
    command_executed: str = ""
    exit_code: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    sandbox_decision_reason: str = Field(default="", description="沙箱策略拒绝原因或 timed_out 等")


class PentestPlaybookResponse(BaseModel):
    """ReAct 收尾阶段：综合观测 + 沙箱真实回显输出授权测试动作与验证结论。"""

    recommendations: list[str] = Field(default_factory=list)
    rationale: str = ""
    evidence: list[PlaybookEvidenceItem] = Field(
        default_factory=list,
        description="与 recommendations 对齐的实测证据；由 execute_verify 沙箱回显填充。",
    )
