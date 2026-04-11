from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.schemas.agent_react import PentestPlaybookResponse
from app.schemas.graph_rag_synthesis import ReActAgentDecision
from app.schemas.probe import ProbeRunRequest
from app.services import probe_service
from app.services.graph_rag_query_service import get_graph_rag_query_service


@dataclass
class AgentStep:
    index: int
    skill_name: str
    input: Dict[str, Any]
    output: Dict[str, Any] | List[Any] | None
    started_at: str
    finished_at: str
    status: str
    thought: str = ""


@dataclass
class AgentRun:
    id: str
    goal: str
    created_at: str
    steps: List[AgentStep]
    final_recommendations: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)


_RUNS: Dict[str, AgentRun] = {}


def _react_system_prompt() -> str:
    return (
        "你是 3GPP 开放暴露面场景下的红队规划智能体（仅授权测试）。"
        "每一步必须输出 JSON，字段为 thought / action / action_input，且满足 ReActAgentDecision Schema。\n"
        "action 取值:\n"
        "- probe: 对目标做 DNS/HTTPS/端口等真实探测；action_input 含 targets（逗号分隔主机名）与可选 context。\n"
        "- graph_rag: 调用图谱+向量混合检索；action_input 含 question（完整问题语句）。\n"
        "- synthesize: 你已掌握足够探测与图谱信息，准备生成最终渗透测试动作建议；action_input 可为空对象。\n"
        "- finish: 结束循环；action_input 可为空对象。\n"
        "策略: 若存在 target_asset，应优先 probe 再 graph_rag；graph_rag 问题必须显式包含协议/网元/服务名等可检索 token。"
    )


async def run_agent(
    goal: str,
    text: str | None = None,
    *,
    target_asset: str | None = None,
    service: str | None = None,
    mcc: str | None = None,
    mnc: str | None = None,
) -> AgentRun:
    """
    ReAct 循环：Reason（LLM 结构化决策） + Act（真实 probe / GraphRAG / 综合 LLM）。
    不再使用写死的 exec_skill 线性流水线。
    """
    run_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    steps: List[AgentStep] = []
    observations: list[dict[str, Any]] = []
    if text:
        observations.append({"kind": "user_text", "content": text[:8000]})
    ctx: dict[str, Any] = {
        "goal": goal,
        "target_asset": target_asset or "",
        "service": service or "",
        "mcc": mcc or "",
        "mnc": mnc or "",
        "observations": observations,
    }
    final_recommendations: list[str] = []

    if not settings.llm_enabled:
        run = AgentRun(
            id=run_id,
            goal=goal,
            created_at=now,
            steps=steps,
            final_recommendations=["LLM 未配置：ReAct 决策与综合无法执行。"],
            context=ctx,
        )
        _RUNS[run_id] = run
        return run

    schema_json = json.dumps(ReActAgentDecision.model_json_schema(), ensure_ascii=False)
    max_turns = 12

    for turn in range(1, max_turns + 1):
        started = datetime.now(timezone.utc).isoformat()
        user_blob = json.dumps(ctx, ensure_ascii=False)
        try:
            llm_res = await get_llm_provider().chat_json(
                system_prompt=_react_system_prompt() + f"\n当前 Schema（action 枚举约束）参考:\n{schema_json}",
                user_prompt=f"当前轮次={turn}。上下文:\n{user_blob}\n只返回 JSON。",
                model_name=settings.llm_model_name,
                temperature=0.2,
            )
            decision = ReActAgentDecision.model_validate(llm_res.raw if isinstance(llm_res.raw, dict) else {})
        except Exception as exc:  # noqa: BLE001
            finished = datetime.now(timezone.utc).isoformat()
            steps.append(
                AgentStep(
                    index=turn,
                    skill_name="react_decision",
                    input={"turn": turn},
                    output={"error": str(exc)},
                    started_at=started,
                    finished_at=finished,
                    status="error",
                    thought="",
                )
            )
            break

        finished = datetime.now(timezone.utc).isoformat()
        out_payload: dict[str, Any] = {}
        status = "ok"

        if decision.action == "probe":
            raw_targets = (decision.action_input.get("targets") or target_asset or "").strip()
            parts = [p.strip() for p in raw_targets.replace(";", ",").split(",") if p.strip()]
            if not parts and target_asset:
                parts = [target_asset.strip()]
            if not parts:
                out_payload = {"error": "no_probe_targets"}
                status = "error"
            else:
                try:
                    pr = await probe_service.run_probe(
                        ProbeRunRequest(targets=parts, context=decision.action_input.get("context") or f"react:{goal[:40]}")
                    )
                    out_payload = pr.model_dump()
                    observations.append({"kind": "probe", "summary": out_payload.get("summary"), "results": out_payload.get("results")})
                except Exception as exc:  # noqa: BLE001
                    out_payload = {"error": str(exc)}
                    status = "error"
        elif decision.action == "graph_rag":
            q = (decision.action_input.get("question") or "").strip()
            if not q:
                out_payload = {"error": "empty_graph_rag_question"}
                status = "error"
            else:
                out_payload = await get_graph_rag_query_service().ask(question=q, top_k=settings.graph_rag_top_k)
                observations.append({"kind": "graph_rag", "question": q, "answer": out_payload})
        elif decision.action == "synthesize":
            pb_schema = json.dumps(PentestPlaybookResponse.model_json_schema(), ensure_ascii=False)
            syn_user = (
                "综合以下观测，输出授权实验室内可执行的渗透测试动作（不要利用脚本、不要非法步骤）。\n"
                f"观测 JSON:\n{json.dumps(observations, ensure_ascii=False)[:12000]}\n"
                f"Schema:\n{pb_schema}\n"
            )
            try:
                syn = await get_llm_provider().chat_json(
                    system_prompt="你是渗透测试编排助手，只输出匹配 Schema 的 JSON。",
                    user_prompt=syn_user,
                    model_name=settings.llm_model_name,
                    temperature=0.2,
                )
                playbook = PentestPlaybookResponse.model_validate(syn.raw if isinstance(syn.raw, dict) else {})
                final_recommendations = list(playbook.recommendations)
                out_payload = playbook.model_dump()
                observations.append({"kind": "synthesize", "playbook": out_payload})
            except Exception as exc:  # noqa: BLE001
                out_payload = {"error": str(exc)}
                status = "error"
        elif decision.action == "finish":
            out_payload = {"done": True}
            steps.append(
                AgentStep(
                    index=turn,
                    skill_name="react_finish",
                    input=dict(decision.action_input),
                    output=out_payload,
                    started_at=started,
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    status="ok",
                    thought=decision.thought,
                )
            )
            ctx["observations"] = observations
            break
        else:
            out_payload = {"error": f"unknown_action:{decision.action}"}
            status = "error"

        ctx["observations"] = observations
        steps.append(
            AgentStep(
                index=turn,
                skill_name=f"react_{decision.action}",
                input=dict(decision.action_input),
                output=out_payload,
                started_at=started,
                finished_at=finished,
                status=status,
                thought=decision.thought,
            )
        )

    run = AgentRun(
        id=run_id,
        goal=goal,
        created_at=now,
        steps=steps,
        final_recommendations=final_recommendations,
        context=ctx,
    )
    _RUNS[run_id] = run
    return run


def list_runs() -> list[dict[str, Any]]:
    return [asdict(r) for r in _RUNS.values()]


def get_run(run_id: str) -> dict[str, Any] | None:
    run = _RUNS.get(run_id)
    return asdict(run) if run else None
