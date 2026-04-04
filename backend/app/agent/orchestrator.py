from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from app.skills.registry import registry


@dataclass
class AgentStep:
    index: int
    skill_name: str
    input: Dict[str, Any]
    output: Dict[str, Any] | List[Any] | None
    started_at: str
    finished_at: str
    status: str


@dataclass
class AgentRun:
    id: str
    goal: str
    created_at: str
    steps: List[AgentStep]


_RUNS: Dict[str, AgentRun] = {}


async def run_agent(goal: str, text: str | None = None) -> AgentRun:
    """
    非复杂规划版 Agent：
    - 如果给了 text：extract_spec_knowledge -> merge_graph_entities -> validate_graph_integrity
    - 然后 build_demo_report
    """
    run_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    steps: List[AgentStep] = []

    async def exec_skill(order: int, name: str, args: Dict[str, Any]) -> Any:
        meta_func = registry.get(name)
        if not meta_func:
            step = AgentStep(
                index=order,
                skill_name=name,
                input=args,
                output={"error": "skill not found"},
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                status="error",
            )
            steps.append(step)
            return None
        meta, func = meta_func
        started = datetime.now(timezone.utc).isoformat()
        try:
            res = func(args)
            if hasattr(res, "__await__"):
                res = await res  # type: ignore[assignment]
            finished = datetime.now(timezone.utc).isoformat()
            if hasattr(res, "model_dump"):
                res = res.model_dump()  # pydantic BaseModel
            step = AgentStep(
                index=order,
                skill_name=meta.name,
                input=args,
                output=res if isinstance(res, (dict, list)) else {"value": str(res)},
                started_at=started,
                finished_at=finished,
                status="ok",
            )
            steps.append(step)
            return res
        except Exception as exc:  # noqa: BLE001
            finished = datetime.now(timezone.utc).isoformat()
            step = AgentStep(
                index=order,
                skill_name=meta.name,
                input=args,
                output={"error": str(exc)},
                started_at=started,
                finished_at=finished,
                status="error",
            )
            steps.append(step)
            return None

    order = 1
    if text:
        extracted = await exec_skill(order, "extract_spec_knowledge", {"text": text})
        order += 1
        if extracted and isinstance(extracted, dict):
            merged = await exec_skill(
                order,
                "merge_graph_entities",
                {
                    "nodes": extracted.get("merged", {}).get("nodes", []),
                    "edges": extracted.get("merged", {}).get("edges", []),
                },
            )
            order += 1
    await exec_skill(order, "validate_graph_integrity", {})
    order += 1
    await exec_skill(order, "build_demo_report", {})

    run = AgentRun(id=run_id, goal=goal, created_at=now, steps=steps)
    _RUNS[run_id] = run
    return run


def list_runs() -> list[dict[str, Any]]:
    return [asdict(r) for r in _RUNS.values()]


def get_run(run_id: str) -> dict[str, Any] | None:
    run = _RUNS.get(run_id)
    return asdict(run) if run else None

