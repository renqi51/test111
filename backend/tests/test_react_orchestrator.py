from __future__ import annotations

from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent import orchestrator


@pytest.mark.asyncio
async def test_react_agent_probe_graph_rag_synthesize_finish() -> None:
    decisions = [
        {"thought": "先探测", "action": "probe", "action_input": {"targets": "lab.example.com"}},
        {"thought": "查规范", "action": "graph_rag", "action_input": {"question": "HTTPS NEF OAuth2 安全要求"}},
        {"thought": "综合", "action": "synthesize", "action_input": {}},
        {"thought": "结束", "action": "finish", "action_input": {}},
    ]
    call = {"i": 0}

    async def _chat_json(**kwargs):  # noqa: ANN003
        from app.providers.llm_provider import LLMExtractResult

        if "渗透测试编排" in str(kwargs.get("system_prompt", "")):
            return LLMExtractResult(
                raw={"recommendations": ["在授权实验室内抓包分析 SIP 注册信令"], "rationale": "t"},
                model="mock",
                provider="mock",
                created_at="",
            )
        idx = call["i"]
        call["i"] += 1
        return LLMExtractResult(raw=decisions[idx], model="mock", provider="mock", created_at="")

    fake_probe = AsyncMock()
    fake_probe.return_value = type(
        "PR",
        (),
        {
            "model_dump": lambda self: {"results": [], "summary": {}},
        },
    )()

    class _GR:
        async def ask(self, **kwargs):  # noqa: ANN003
            return {"answer": "需校验 OAuth2 绑定", "confidence": 0.5, "citations": [], "notes": []}

    mock_settings = MagicMock()
    mock_settings.llm_enabled = True
    mock_settings.graph_rag_top_k = 5
    mock_settings.llm_model_name = "mock-model"

    with (
        patch("app.agent.orchestrator.settings", mock_settings),
        patch("app.agent.orchestrator.get_llm_provider") as m_llm,
        patch("app.agent.orchestrator.probe_service.run_probe", fake_probe),
        patch("app.agent.orchestrator.get_graph_rag_query_service", return_value=_GR()),
    ):
        prov = m_llm.return_value
        prov.chat_json = AsyncMock(side_effect=_chat_json)
        run = await orchestrator.run_agent(
            goal="分析暴露面",
            target_asset="lab.example.com",
            service="IMS",
            mcc="460",
            mnc="01",
        )
    d = asdict(run)
    assert d["final_recommendations"]
    assert any(s["skill_name"] == "react_probe" for s in d["steps"])
    assert any(s["skill_name"] == "react_graph_rag" for s in d["steps"])
    assert any(s["skill_name"] == "react_synthesize" for s in d["steps"])
    assert any(s["skill_name"] == "react_finish" for s in d["steps"])
