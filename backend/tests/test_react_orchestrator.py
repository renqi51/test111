from __future__ import annotations

from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent import orchestrator
from app.agent.orchestrator import _react_system_prompt, _sanitize_llm_shell_command


def test_sanitize_llm_shell_command_strips_markdown_fence() -> None:
    raw = "```bash\necho 192.0.2.1\n```"
    assert _sanitize_llm_shell_command(raw) == "echo 192.0.2.1"


def test_react_system_prompt_mandates_probe_before_graph_rag() -> None:
    p = _react_system_prompt()
    assert "Recon" in p and "Weaponize" in p and "Exploit Plan" in p
    assert "必须先 action=probe" in p or "必须先" in p
    assert "execute_verify" in p


@pytest.mark.asyncio
async def test_react_agent_probe_graph_rag_synthesize_finish() -> None:
    decisions = [
        {"thought": "先探测", "action": "probe", "action_input": {"targets": "lab.example.com"}},
        {
            "thought": "Weaponize",
            "action": "graph_rag",
            "action_input": {
                "question": "针对边界暴露的 HTTPS/443、IKEv2/UDP500 在图谱中有哪些已知漏洞、威胁向量与可验证的利用前置条件？",
            },
        },
        {"thought": "综合", "action": "synthesize", "action_input": {}},
        {
            "thought": "沙箱验证",
            "action": "execute_verify",
            "action_input": {"command": "echo 192.0.2.1", "title": "smoke"},
        },
        {"thought": "结束", "action": "finish", "action_input": {}},
    ]
    call = {"i": 0}

    async def _chat_json(**kwargs):  # noqa: ANN003
        from app.providers.llm_provider import LLMExtractResult

        if "攻击性渗透测试编排助手" in str(kwargs.get("system_prompt", "")):
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

    fake_sandbox = AsyncMock(
        return_value={
            "allowed": True,
            "blocked": False,
            "exit_code": 0,
            "stdout": "sandbox-stdout",
            "stderr": "",
            "timed_out": False,
            "reason": "executed",
        }
    )

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
        patch("app.agent.orchestrator.exploit_sandbox_service.run_sandbox_command", fake_sandbox),
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
    assert any(s["skill_name"] == "react_execute_verify" for s in d["steps"])
    assert any(s["skill_name"] == "react_finish" and s.get("status") == "ok" for s in d["steps"])
    assert d.get("final_playbook", {}).get("evidence")
    assert d["final_playbook"]["evidence"][0].get("validation_status") == "Validated_Success"


@pytest.mark.asyncio
async def test_finish_blocked_without_execute_verify_then_recover() -> None:
    """synthesize 后若直接 finish 应被拒绝；下一轮 execute_verify 后再 finish 成功。"""
    decisions = [
        {"thought": "p", "action": "probe", "action_input": {"targets": "lab.example.com"}},
        {
            "thought": "g",
            "action": "graph_rag",
            "action_input": {
                "question": "针对边界暴露的 HTTPS/443 在图谱中有哪些已知漏洞、威胁向量与可验证的利用前置条件？",
            },
        },
        {"thought": "s", "action": "synthesize", "action_input": {}},
        {"thought": "bad finish", "action": "finish", "action_input": {}},
        {"thought": "ev", "action": "execute_verify", "action_input": {"command": "echo 192.0.2.1"}},
        {"thought": "ok finish", "action": "finish", "action_input": {}},
    ]
    call = {"i": 0}

    async def _chat_json(**kwargs):  # noqa: ANN003
        from app.providers.llm_provider import LLMExtractResult

        if "攻击性渗透测试编排助手" in str(kwargs.get("system_prompt", "")):
            return LLMExtractResult(
                raw={"recommendations": ["r1"], "rationale": "x"},
                model="mock",
                provider="mock",
                created_at="",
            )
        idx = call["i"]
        call["i"] += 1
        return LLMExtractResult(raw=decisions[idx], model="mock", provider="mock", created_at="")

    fake_probe = AsyncMock()
    fake_probe.return_value = type("PR", (), {"model_dump": lambda self: {"results": [], "summary": {}}})()

    fake_sandbox = AsyncMock(
        return_value={
            "allowed": True,
            "blocked": False,
            "exit_code": 0,
            "stdout": "ok",
            "stderr": "",
            "timed_out": False,
            "reason": "executed",
        }
    )

    class _GR:
        async def ask(self, **kwargs):  # noqa: ANN003
            return {"answer": "a", "confidence": 0.5, "citations": [], "notes": []}

    mock_settings = MagicMock()
    mock_settings.llm_enabled = True
    mock_settings.graph_rag_top_k = 5
    mock_settings.llm_model_name = "mock-model"

    with (
        patch("app.agent.orchestrator.settings", mock_settings),
        patch("app.agent.orchestrator.get_llm_provider") as m_llm,
        patch("app.agent.orchestrator.probe_service.run_probe", fake_probe),
        patch("app.agent.orchestrator.exploit_sandbox_service.run_sandbox_command", fake_sandbox),
        patch("app.agent.orchestrator.get_graph_rag_query_service", return_value=_GR()),
    ):
        m_llm.return_value.chat_json = AsyncMock(side_effect=_chat_json)
        run = await orchestrator.run_agent(goal="g", target_asset="lab.example.com")
    d = asdict(run)
    assert any(
        s.get("output", {}).get("error") == "finish_blocked_missing_successful_execute_verify" for s in d["steps"]
    )
    assert d["final_playbook"].get("evidence")


@pytest.mark.asyncio
async def test_execute_verify_strips_markdown_before_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    decisions = [
        {"thought": "p", "action": "probe", "action_input": {"targets": "lab.example.com"}},
        {
            "thought": "g",
            "action": "graph_rag",
            "action_input": {
                "question": "针对边界暴露的 HTTPS/443 在图谱中有哪些已知漏洞、威胁向量与可验证的利用前置条件？",
            },
        },
        {"thought": "s", "action": "synthesize", "action_input": {}},
        {
            "thought": "ev",
            "action": "execute_verify",
            "action_input": {"command": "```bash\necho 192.0.2.1\n```"},
        },
        {"thought": "f", "action": "finish", "action_input": {}},
    ]
    call = {"i": 0}

    async def _chat_json(**kwargs):  # noqa: ANN003
        from app.providers.llm_provider import LLMExtractResult

        if "攻击性渗透测试编排助手" in str(kwargs.get("system_prompt", "")):
            return LLMExtractResult(
                raw={"recommendations": ["r1"], "rationale": "x"},
                model="mock",
                provider="mock",
                created_at="",
            )
        idx = call["i"]
        call["i"] += 1
        return LLMExtractResult(raw=decisions[idx], model="mock", provider="mock", created_at="")

    fake_probe = AsyncMock()
    fake_probe.return_value = type("PR", (), {"model_dump": lambda self: {"results": [], "summary": {}}})()

    fake_sandbox = AsyncMock(
        return_value={
            "allowed": True,
            "blocked": False,
            "exit_code": 0,
            "stdout": "ok",
            "stderr": "",
            "timed_out": False,
            "reason": "executed",
        }
    )

    class _GR:
        async def ask(self, **kwargs):  # noqa: ANN003
            return {"answer": "a", "confidence": 0.5, "citations": [], "notes": []}

    mock_settings = MagicMock()
    mock_settings.llm_enabled = True
    mock_settings.graph_rag_top_k = 5
    mock_settings.llm_model_name = "mock-model"

    with (
        patch("app.agent.orchestrator.settings", mock_settings),
        patch("app.agent.orchestrator.get_llm_provider") as m_llm,
        patch("app.agent.orchestrator.probe_service.run_probe", fake_probe),
        patch("app.agent.orchestrator.exploit_sandbox_service.run_sandbox_command", fake_sandbox),
        patch("app.agent.orchestrator.get_graph_rag_query_service", return_value=_GR()),
    ):
        m_llm.return_value.chat_json = AsyncMock(side_effect=_chat_json)
        await orchestrator.run_agent(goal="g", target_asset="lab.example.com")

    fake_sandbox.assert_awaited()
    called_cmd = fake_sandbox.await_args_list[0].args[0]
    assert called_cmd == "echo 192.0.2.1"
    assert "```" not in called_cmd


@pytest.mark.asyncio
async def test_three_consecutive_sandbox_blocks_abort_run(monkeypatch: pytest.MonkeyPatch) -> None:
    decisions = [
        {"thought": "p", "action": "probe", "action_input": {"targets": "lab.example.com"}},
        {
            "thought": "g",
            "action": "graph_rag",
            "action_input": {
                "question": "针对边界暴露的 HTTPS/443 在图谱中有哪些已知漏洞、威胁向量与可验证的利用前置条件？",
            },
        },
        {"thought": "s", "action": "synthesize", "action_input": {}},
        {"thought": "b1", "action": "execute_verify", "action_input": {"command": "echo 192.0.2.1"}},
        {"thought": "b2", "action": "execute_verify", "action_input": {"command": "echo 192.0.2.1"}},
        {"thought": "b3", "action": "execute_verify", "action_input": {"command": "echo 192.0.2.1"}},
    ]
    call = {"i": 0}

    async def _chat_json(**kwargs):  # noqa: ANN003
        from app.providers.llm_provider import LLMExtractResult

        if "攻击性渗透测试编排助手" in str(kwargs.get("system_prompt", "")):
            return LLMExtractResult(
                raw={"recommendations": ["r1"], "rationale": "x"},
                model="mock",
                provider="mock",
                created_at="",
            )
        idx = call["i"]
        call["i"] += 1
        return LLMExtractResult(raw=decisions[idx], model="mock", provider="mock", created_at="")

    fake_probe = AsyncMock()
    fake_probe.return_value = type("PR", (), {"model_dump": lambda self: {"results": [], "summary": {}}})()

    fake_sandbox = AsyncMock(
        return_value={
            "allowed": False,
            "blocked": True,
            "reason": "shell_metacharacter_forbidden:';'",
            "exit_code": None,
            "stdout": "",
            "stderr": "",
        }
    )

    class _GR:
        async def ask(self, **kwargs):  # noqa: ANN003
            return {"answer": "a", "confidence": 0.5, "citations": [], "notes": []}

    mock_settings = MagicMock()
    mock_settings.llm_enabled = True
    mock_settings.graph_rag_top_k = 5
    mock_settings.llm_model_name = "mock-model"

    with (
        patch("app.agent.orchestrator.settings", mock_settings),
        patch("app.agent.orchestrator.get_llm_provider") as m_llm,
        patch("app.agent.orchestrator.probe_service.run_probe", fake_probe),
        patch("app.agent.orchestrator.exploit_sandbox_service.run_sandbox_command", fake_sandbox),
        patch("app.agent.orchestrator.get_graph_rag_query_service", return_value=_GR()),
    ):
        m_llm.return_value.chat_json = AsyncMock(side_effect=_chat_json)
        run = await orchestrator.run_agent(goal="g", target_asset="lab.example.com")

    d = asdict(run)
    assert any(s.get("output", {}).get("aborted") is True for s in d["steps"])
    assert fake_sandbox.await_count == 3


@pytest.mark.asyncio
async def test_finish_blocked_when_sandbox_exit_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    """沙箱已执行但 exit_code!=0 时不应允许 finish。"""
    decisions = [
        {"thought": "p", "action": "probe", "action_input": {"targets": "lab.example.com"}},
        {
            "thought": "g",
            "action": "graph_rag",
            "action_input": {
                "question": "针对边界暴露的 HTTPS/443 在图谱中有哪些已知漏洞、威胁向量与可验证的利用前置条件？",
            },
        },
        {"thought": "s", "action": "synthesize", "action_input": {}},
        {"thought": "ev bad", "action": "execute_verify", "action_input": {"command": "echo 192.0.2.1"}},
        {"thought": "finish too early", "action": "finish", "action_input": {}},
        {"thought": "ev ok", "action": "execute_verify", "action_input": {"command": "echo 192.0.2.1"}},
        {"thought": "finish ok", "action": "finish", "action_input": {}},
    ]
    call = {"i": 0}
    sandbox_round = {"n": 0}

    async def _chat_json(**kwargs):  # noqa: ANN003
        from app.providers.llm_provider import LLMExtractResult

        if "攻击性渗透测试编排助手" in str(kwargs.get("system_prompt", "")):
            return LLMExtractResult(
                raw={"recommendations": ["r1"], "rationale": "x"},
                model="mock",
                provider="mock",
                created_at="",
            )
        idx = call["i"]
        call["i"] += 1
        return LLMExtractResult(raw=decisions[idx], model="mock", provider="mock", created_at="")

    async def _sandbox(cmd: str) -> dict:  # noqa: ANN401
        sandbox_round["n"] += 1
        if sandbox_round["n"] == 1:
            return {
                "allowed": True,
                "blocked": False,
                "exit_code": 7,
                "stdout": "",
                "stderr": "fail",
                "timed_out": False,
                "reason": "executed",
            }
        return {
            "allowed": True,
            "blocked": False,
            "exit_code": 0,
            "stdout": "ok",
            "stderr": "",
            "timed_out": False,
            "reason": "executed",
        }

    fake_probe = AsyncMock()
    fake_probe.return_value = type("PR", (), {"model_dump": lambda self: {"results": [], "summary": {}}})()

    class _GR:
        async def ask(self, **kwargs):  # noqa: ANN003
            return {"answer": "a", "confidence": 0.5, "citations": [], "notes": []}

    mock_settings = MagicMock()
    mock_settings.llm_enabled = True
    mock_settings.graph_rag_top_k = 5
    mock_settings.llm_model_name = "mock-model"

    with (
        patch("app.agent.orchestrator.settings", mock_settings),
        patch("app.agent.orchestrator.get_llm_provider") as m_llm,
        patch("app.agent.orchestrator.probe_service.run_probe", fake_probe),
        patch("app.agent.orchestrator.exploit_sandbox_service.run_sandbox_command", AsyncMock(side_effect=_sandbox)),
        patch("app.agent.orchestrator.get_graph_rag_query_service", return_value=_GR()),
    ):
        m_llm.return_value.chat_json = AsyncMock(side_effect=_chat_json)
        run = await orchestrator.run_agent(goal="g", target_asset="lab.example.com")

    d = asdict(run)
    errs = [s for s in d["steps"] if s.get("skill_name") == "react_finish" and s.get("status") == "error"]
    assert errs and errs[0].get("output", {}).get("error") == "finish_blocked_missing_successful_execute_verify"
    oks = [s for s in d["steps"] if s.get("skill_name") == "react_finish" and s.get("status") == "ok"]
    assert oks
