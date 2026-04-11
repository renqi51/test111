from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.agent.orchestrator import get_run, list_runs, run_agent

router = APIRouter(tags=["agent"])


@router.post("/agent/run")
async def agent_run(body: dict):
    goal = body.get("goal") or "unspecified goal"
    text = body.get("text")
    run = await run_agent(
        goal=goal,
        text=text,
        target_asset=body.get("target_asset"),
        service=body.get("service"),
        mcc=body.get("mcc"),
        mnc=body.get("mnc"),
    )
    return {"run": run}


@router.get("/agent/runs")
def agent_runs():
    return {"runs": list_runs()}


@router.get("/agent/runs/{run_id}")
def agent_run_detail(run_id: str):
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run": run}

