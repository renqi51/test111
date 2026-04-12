from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.schemas.agent_react import PentestPlaybookResponse, PlaybookEvidenceItem
from app.schemas.graph_rag_synthesis import ReActAgentDecision
from app.schemas.probe import ProbeRunRequest
from app.services import exploit_sandbox_service, probe_service
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
    # 含 recommendations + evidence（沙箱实测），便于前端与审计消费完整结构化结果。
    final_playbook: Dict[str, Any] = field(default_factory=dict)


_RUNS: Dict[str, AgentRun] = {}


def _react_system_prompt() -> str:
    return (
        "你是 5G 核心网 / Open Gateway 场景的红队编排智能体，仅在授权实验室内行动。\n"
        "每一步必须输出 JSON：thought / action / action_input，且满足 ReActAgentDecision Schema。\n\n"
        "强制打法链路（不得跳步、不得凭空调 graph_rag）：\n"
        "1) Recon — 若上下文中尚无 kind=probe 的观测，或 targets 未覆盖用户给定 target_asset，"
        "必须先 action=probe：action_input.targets 为逗号/分号分隔主机或 IP；"
        "用真实探测结果（开放端口、udp_spike_findings、tcp_banners、HTTPS 状态）建立资产面。\n"
        "2) Weaponize — 在完成 probe 后，必须至少一次 action=graph_rag，且 question 必须严格采用模板：\n"
        "   「针对边界暴露的 [协议或端口列表，来自 probe] 在图谱中有哪些已知漏洞、威胁向量与可验证的利用前置条件？」\n"
        "   将 [协议或端口列表] 替换为观测中的具体 token（如 IKEv2/UDP500、GTP-U/2152、SIP/TCP5060、HTTPS/443）。\n"
        "3) Exploit Plan — 在已有 graph_rag 答案后，才能 action=synthesize："
        "综合 probe + graph_rag，输出可落地的验证动作、抓包点位、畸形用例思路、DoS/越权验证路径（仍限于授权靶场）。\n"
        "4) Trigger — synthesize 成功后，下一轮必须 action=execute_verify："
        "action_input.command 填一条完整 shell（须含字面目标 IP 以通过 CIDR 白名单，例如 nmap -sU -p500 192.0.2.1）；"
        "可选 action_input.title 描述验证点。\n"
        "5) finish — 仅当 observations 中已存在 kind=sandbox_execute（沙箱真实回显）后，才允许 action=finish；"
        "最终结论必须基于沙箱 stdout/stderr，不得编造未执行命令的结果。\n\n"
        "action 枚举:\n"
        "- probe: action_input.targets（必填）, 可选 context。\n"
        "- graph_rag: action_input.question（必填，且符合 Weaponize 模板）。\n"
        "- synthesize: action_input 可为 {}。\n"
        "- execute_verify: action_input.command（必填，单行 shell）；底层为 asyncio.create_subprocess_shell + 超时 + CIDR 校验。\n"
        "- finish: action_input 可为 {}。\n"
        "禁止：在未执行 probe 前调用 graph_rag；在缺少 graph_rag 时调用 synthesize；"
        "在缺少 sandbox_execute 时调用 finish；编造未出现在观测中的端口/协议。"
    )


def _evidence_from_sandbox_result(title: str, cmd: str, result: dict[str, Any]) -> PlaybookEvidenceItem:
    """将沙箱原始 dict 转为 PlaybookEvidenceItem；validation_status 完全由真实回显与退出码推导。"""
    if result.get("blocked"):
        return PlaybookEvidenceItem(
            title=title or "sandbox",
            validation_status="Skipped",
            command_executed=cmd,
            sandbox_decision_reason=str(result.get("reason") or "blocked"),
        )
    if result.get("timed_out"):
        return PlaybookEvidenceItem(
            title=title or "sandbox",
            validation_status="Validated_Failed",
            command_executed=cmd,
            exit_code=None,
            stdout_excerpt=str(result.get("stdout") or ""),
            stderr_excerpt=str(result.get("stderr") or ""),
            sandbox_decision_reason=str(result.get("reason") or "timed_out"),
        )
    code = result.get("exit_code")
    ok = code == 0
    return PlaybookEvidenceItem(
        title=title or "sandbox",
        validation_status="Validated_Success" if ok else "Validated_Failed",
        command_executed=cmd,
        exit_code=code if isinstance(code, int) else None,
        stdout_excerpt=str(result.get("stdout") or "")[:4000],
        stderr_excerpt=str(result.get("stderr") or "")[:4000],
        sandbox_decision_reason=str(result.get("reason") or "executed"),
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
    ReAct 循环：Reason（LLM 结构化决策） + Act（真实 probe / GraphRAG / 综合 LLM / 沙箱 execute_verify）。
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
        "synth_done": False,
        "sandbox_done": False,
        "playbook_evidence": [],
        "last_rationale": "",
    }
    final_recommendations: list[str] = []
    final_playbook: dict[str, Any] = {}

    if not settings.llm_enabled:
        run = AgentRun(
            id=run_id,
            goal=goal,
            created_at=now,
            steps=steps,
            final_recommendations=["LLM 未配置：ReAct 决策与综合无法执行。"],
            context=ctx,
            final_playbook=final_playbook,
        )
        _RUNS[run_id] = run
        return run

    schema_json = json.dumps(ReActAgentDecision.model_json_schema(), ensure_ascii=False)
    max_turns = 14

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
                "你是红队 Exploit Planning 阶段：综合以下观测（含 probe 的端口、udp_spike_findings、tcp_banners 与 graph_rag），"
                "输出仅在授权实验室内可执行的步骤；每条 recommendation 必须具体到工具/参数/抓包过滤表达式/发包字段偏移思路，"
                "例如 nmap -sU -p 500 --script ike-version、对 SIP OPTIONS 响应做 CSeq 重放、对畸形 IKE major 版本观察 NOTIFY 类型等。\n"
                f"观测 JSON:\n{json.dumps(observations, ensure_ascii=False)[:12000]}\n"
                f"Schema:\n{pb_schema}\n"
            )
            try:
                syn = await get_llm_provider().chat_json(
                    system_prompt="你是攻击性渗透测试编排助手：只输出匹配 Schema 的 JSON；recommendations 必须可执行且指向验证而非实际未授权利用。",
                    user_prompt=syn_user,
                    model_name=settings.llm_model_name,
                    temperature=0.2,
                )
                playbook = PentestPlaybookResponse.model_validate(syn.raw if isinstance(syn.raw, dict) else {})
                final_recommendations = list(playbook.recommendations)
                ctx["last_rationale"] = playbook.rationale or ""
                out_payload = playbook.model_dump()
                observations.append({"kind": "synthesize", "playbook": out_payload})
                ctx["synth_done"] = True
            except Exception as exc:  # noqa: BLE001
                out_payload = {"error": str(exc)}
                status = "error"
        elif decision.action == "execute_verify":
            # command: 单行 shell，将交给 exploit_sandbox_service 做 CIDR/黑名单校验后再 create_subprocess_shell。
            cmd = (decision.action_input.get("command") or decision.action_input.get("cmd") or "").strip()
            title = (decision.action_input.get("title") or "execute_verify").strip()
            if not cmd:
                out_payload = {"error": "empty_execute_verify_command"}
                status = "error"
            else:
                result = await exploit_sandbox_service.run_sandbox_command(cmd)
                out_payload = result
                observations.append({"kind": "sandbox_execute", "command": cmd, "result": result})
                ev = _evidence_from_sandbox_result(title, cmd, result)
                ctx["playbook_evidence"].append(ev.model_dump())
                ctx["sandbox_done"] = True
        elif decision.action == "finish":
            if ctx.get("synth_done") and not ctx.get("sandbox_done"):
                out_payload = {
                    "error": "finish_blocked_missing_execute_verify",
                    "hint": "必须先执行 action=execute_verify 并产生 kind=sandbox_execute 观测后再 finish。",
                }
                status = "error"
                steps.append(
                    AgentStep(
                        index=turn,
                        skill_name="react_finish",
                        input=dict(decision.action_input),
                        output=out_payload,
                        started_at=started,
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        status="error",
                        thought=decision.thought,
                    )
                )
                ctx["observations"] = observations
                continue
            else:
                out_payload = {"done": True}
                evidence_objs = [PlaybookEvidenceItem.model_validate(x) for x in ctx.get("playbook_evidence", [])]
                fp = PentestPlaybookResponse(
                    recommendations=final_recommendations,
                    rationale=ctx.get("last_rationale", ""),
                    evidence=evidence_objs,
                )
                final_playbook = fp.model_dump()
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
        if decision.action != "finish":
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

    if not final_playbook and final_recommendations:
        evidence_objs = [PlaybookEvidenceItem.model_validate(x) for x in ctx.get("playbook_evidence", [])]
        final_playbook = PentestPlaybookResponse(
            recommendations=final_recommendations,
            rationale=ctx.get("last_rationale", ""),
            evidence=evidence_objs,
        ).model_dump()

    run = AgentRun(
        id=run_id,
        goal=goal,
        created_at=now,
        steps=steps,
        final_recommendations=final_recommendations,
        context=ctx,
        final_playbook=final_playbook,
    )
    _RUNS[run_id] = run
    return run


def list_runs() -> list[dict[str, Any]]:
    return [asdict(r) for r in _RUNS.values()]


def get_run(run_id: str) -> dict[str, Any] | None:
    run = _RUNS.get(run_id)
    return asdict(run) if run else None
