from __future__ import annotations

from pydantic import BaseModel, Field


class PentestPlaybookResponse(BaseModel):
    """ReAct 收尾阶段：综合观测输出授权测试动作。"""

    recommendations: list[str] = Field(default_factory=list)
    rationale: str = ""
