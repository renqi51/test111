from __future__ import annotations

from fastapi import APIRouter

from app.skills.registry import registry

router = APIRouter(tags=["mcp"])


@router.get("/mcp/tools")
def mcp_tools():
    """
    MCP-like 工具发现接口（简化版）：
    返回所有已注册 skill 的 tool schema，便于前端或 agent 动态选择工具。
    """
    return {
        "tools": registry.list_tools(),
        "generated_by": "SkillRegistry",
    }

