from __future__ import annotations

import logging
import traceback
from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict

from app.agent.orchestrator import AgentRun, get_run, list_runs, run_agent

router = APIRouter(tags=["agent"])
logger = logging.getLogger(__name__)


def _strip_str(v: object) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _default_goal_from_asset(target_asset: str) -> str:
    return (
        f"对授权目标「{target_asset}」在策略允许范围内自主完成暴露面探测（probe：DNS/端口/HTTPS/SCTP 等），"
        "必要时结合 GraphRAG 与图谱，输出端口与协议事实、风险假设与可复核验证建议。"
    )


class AgentRunRequest(BaseModel):
    """POST /api/agent/run 请求体；字段均可选除「goal 与 target_asset 至少填一个」由路由校验。"""

    model_config = ConfigDict(extra="ignore")

    goal: str | None = None
    text: str | None = None
    target_asset: str | None = None
    service: str | None = None
    mcc: str | None = None
    mnc: str | None = None


def _run_to_response_dict(run: AgentRun) -> dict:
    """保证 HTTP JSON 可编码（避免嵌套 dataclass / 非标准类型导致响应阶段 500）。"""
    return jsonable_encoder(asdict(run))


def _format_agent_failure(exc: BaseException) -> str:
    """TimeoutError / ValueError() 等 str(exc) 常为空，避免前端只显示「执行失败：」。"""
    name = type(exc).__name__
    body = str(exc).strip()
    if not body:
        body = repr(exc)
    if body in ("", name + "()", "TimeoutError()"):
        if isinstance(exc, TimeoutError):
            body = "等待 LLM 或外部服务超时（可与上游超时、代理断开有关）。"
        else:
            body = f"{name}（无 message，请查看终端日志中的 Traceback）"
    tail = traceback.format_exc()
    if tail and tail.strip() != "NoneType: None":
        lines = [ln for ln in tail.strip().splitlines() if ln.strip()][-12:]
        body = f"{body}\n---\n" + "\n".join(lines)
    return f"[{name}] {body}"[:4500]


@router.post("/agent/run")
async def agent_run(body: AgentRunRequest):
    goal_in = _strip_str(body.goal)
    target_asset = _strip_str(body.target_asset)
    if not goal_in and not target_asset:
        raise HTTPException(
            status_code=422,
            detail="请至少提供 target_asset（资产）或 goal（任务说明）之一；仅填资产即可启动自主探测。",
        )
    goal = goal_in or _default_goal_from_asset(target_asset)
    text_raw = body.text
    text = _strip_str(text_raw) if text_raw is not None else None
    text = text or None
    try:
        run = await run_agent(
            goal=goal,
            text=text,
            target_asset=target_asset or None,
            service=_strip_str(body.service) or None,
            mcc=_strip_str(body.mcc) or None,
            mnc=_strip_str(body.mnc) or None,
        )
        return {"run": _run_to_response_dict(run)}
    except HTTPException:
        raise
    except TimeoutError as exc:
        logger.exception("agent_run timeout: %s", exc)
        raise HTTPException(
            status_code=504,
            detail=_format_agent_failure(exc),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("agent_run failed: %s", exc)
        raise HTTPException(status_code=500, detail=_format_agent_failure(exc)) from exc


@router.get("/agent/runs")
def agent_runs():
    return {"runs": list_runs()}


@router.get("/agent/runs/{run_id}")
def agent_run_detail(run_id: str):
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run": run}

