"""ReAct 发给 LLM 的上下文体积控制（避免超大 JSON 导致网关断开）。"""

from __future__ import annotations

from app.agent.orchestrator import (
    _build_react_user_blob,
    _compact_observations_for_llm,
    _finish_violation_zh,
    _pipeline_next_reminder_zh,
)


def test_compact_probe_strips_long_findings() -> None:
    row = {
        "target": "127.0.0.1",
        "host": "127.0.0.1",
        "permitted": True,
        "policy_reason": "ok",
        "dns_ok": True,
        "udp_spike_findings": [f"line-{i}-" + "x" * 300 for i in range(50)],
        "sctp_probe_findings": ["a"],
        "tcp_banners": {"443": "b" * 2000},
        "sbi_unauth_probe": {"paths": {"/nrf": {"status": 401, "http_version": "HTTP/2"}}},
    }
    slim = _compact_observations_for_llm([{"kind": "probe", "summary": {"x": 1}, "results": [row]}])
    assert slim[0]["kind"] == "probe"
    lines = slim[0]["results"][0]["udp_spike_findings"]
    assert len(lines) <= 26  # 24 + truncation notice
    assert all(len(x) <= 223 for x in lines if not x.startswith("...("))
    assert len(slim[0]["results"][0]["tcp_banners"]["443"]) <= 603


def test_build_react_user_blob_bounded() -> None:
    fat = {
        "goal": "g",
        "target_asset": "127.0.0.1",
        "service": "",
        "mcc": "",
        "mnc": "",
        "synth_done": False,
        "sandbox_done": False,
        "sandbox_success": False,
        "sandbox_policy_block_streak": 0,
        "playbook_evidence": [],
        "last_rationale": "",
        "observations": [
            {
                "kind": "probe",
                "summary": {"n": 1},
                "results": [
                    {
                        "target": "127.0.0.1",
                        "host": "127.0.0.1",
                        "permitted": True,
                        "policy_reason": "x",
                        "dns_ok": True,
                        "udp_spike_findings": [f"L{i}" * 80 for i in range(40)],
                        "sctp_probe_findings": [],
                        "tcp_banners": {},
                        "sbi_unauth_probe": {},
                    }
                ],
            }
        ],
    }
    blob = _build_react_user_blob(fat)
    assert len(blob) <= 33000


def test_compact_preserves_policy_violation_zh() -> None:
    slim = _compact_observations_for_llm(
        [{"kind": "orchestrator_policy_violation", "zh": "禁止 finish：尚未执行 graph_rag。"}]
    )
    assert slim[0]["kind"] == "orchestrator_policy_violation"
    assert "graph_rag" in slim[0]["zh"]


def test_pipeline_reminder_after_probe_requires_graph_rag() -> None:
    obs = [{"kind": "probe", "summary": {}, "results": []}]
    ctx: dict = {"sandbox_success": False, "synth_done": False}
    z = _pipeline_next_reminder_zh(obs, ctx)
    assert "graph_rag" in z
    assert "禁止" in z or "必须" in z


def test_finish_violation_when_no_graph_rag() -> None:
    obs = [{"kind": "probe"}]
    ctx: dict = {"synth_done": False, "sandbox_success": False}
    assert "graph_rag" in _finish_violation_zh(obs, ctx)
