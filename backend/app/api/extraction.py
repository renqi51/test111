from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.extraction_pipeline import (
    ExtractionRunRequest,
    ExtractionRunResponse,
    MergeRequest,
)
from app.services.llm_orchestrator_service import llm_orchestrator_service
from app.services.merge_service import merge_service
from app.services.repair_service import repair_service
from app.services.trace_service import trace_service
from app.repositories.graph_repository import get_graph_repository

router = APIRouter(tags=["extraction"])


@router.post("/extraction/run", response_model=ExtractionRunResponse)
async def extraction_run(body: ExtractionRunRequest):
    return await llm_orchestrator_service.run(body)


@router.get("/extraction/runs")
def extraction_runs(limit: int = 20):
    return {"runs": trace_service.list_runs(limit=limit)}


@router.get("/extraction/prompts")
def extraction_prompts():
    return llm_orchestrator_service.get_prompts()


@router.get("/extraction/status")
def extraction_status():
    return llm_orchestrator_service.get_status()


@router.get("/extraction/{run_id}")
def extraction_detail(run_id: str):
    payload = trace_service.load_run(run_id)
    if not payload:
        raise HTTPException(status_code=404, detail="run not found")
    return payload


@router.get("/extraction/{run_id}/trace")
def extraction_trace(run_id: str):
    return trace_service.load_trace(run_id)


@router.get("/extraction/{run_id}/report")
def extraction_report(run_id: str):
    report = trace_service.load_report(run_id)
    if not report:
        raise HTTPException(status_code=404, detail="report not found")
    return {"run_id": run_id, "markdown": report}


@router.get("/extraction/{run_id}/staging-diff")
def extraction_staging_diff(run_id: str):
    run = trace_service.load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    repo = get_graph_repository()
    staging_payload = repo.get_staging_graph(run_id)
    if not staging_payload:
        raise HTTPException(status_code=400, detail="staging graph missing")
    main_graph = repo.get_graph()
    main_node_ids = {n.get("id") for n in main_graph.get("nodes", [])}
    main_edges = {
        (e.get("source"), e.get("target"), e.get("interaction"))
        for e in main_graph.get("edges", [])
    }
    node_diff = []
    for n in staging_payload.get("nodes", []):
        node_diff.append({"id": n.get("id"), "label": n.get("label"), "status": "existing" if n.get("id") in main_node_ids else "new"})
    edge_diff = []
    for e in staging_payload.get("edges", []):
        key = (e.get("source"), e.get("target"), e.get("interaction"))
        edge_diff.append({"id": f"{key[0]}->{key[2]}->{key[1]}", "source": key[0], "target": key[1], "interaction": key[2], "status": "existing" if key in main_edges else "new"})
    return {
        "run_id": run_id,
        "node_diff": node_diff,
        "edge_diff": edge_diff,
        "summary": {
            "new_nodes": len([x for x in node_diff if x["status"] == "new"]),
            "new_edges": len([x for x in edge_diff if x["status"] == "new"]),
        },
    }


@router.post("/extraction/{run_id}/merge")
def extraction_merge(run_id: str, body: MergeRequest):
    run = trace_service.load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    repo = get_graph_repository()
    staging_payload = repo.get_staging_graph(run_id)
    if not staging_payload:
        raise HTTPException(status_code=400, detail="staging graph missing")
    from app.schemas.extraction_pipeline import StagingGraph

    staging = StagingGraph.model_validate(staging_payload)
    merged = merge_service.merge_staging(run_id=run_id, staging=staging, req=body)
    run["merge_result"] = merged.model_dump()
    trace_service.save_run(run_id, run)
    return merged


@router.post("/extraction/{run_id}/repair")
def extraction_repair(run_id: str):
    run = trace_service.load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    judge = run.get("judge")
    workers = run.get("worker_results") or []
    if not judge or not workers:
        raise HTTPException(status_code=400, detail="judge/workers missing")
    from app.schemas.extraction_pipeline import ConflictItem, ExtractionResult, JudgeDecision

    judge_obj = JudgeDecision.model_validate(judge)
    worker_map = {w.get("worker_name"): w for w in workers}
    preferred_raw = worker_map.get(judge_obj.recommended_worker) or workers[0]
    preferred = ExtractionResult.model_validate(preferred_raw)
    repaired = repair_service.repair(
        run_id=run_id,
        preferred_result=preferred,
        conflicts=[ConflictItem.model_validate(c) for c in judge_obj.conflict_set],
        judge=judge_obj,
    )
    run["repair"] = repaired.model_dump()
    trace_service.save_run(run_id, run)
    return repaired



