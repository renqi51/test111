from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.schemas.p0_ops import AssetUpsertRequest, ScanJobCreateRequest
from app.services.auth_service import AuthContext, require_role
from app.services import p0_ops_service

router = APIRouter(prefix="/p0", tags=["p0"])


@router.get("/assets")
def p0_assets(_: AuthContext = Depends(require_role("admin", "operator", "viewer"))):
    return {"assets": [x.model_dump(mode="json") for x in p0_ops_service.list_assets()]}


@router.post("/assets/upsert")
def p0_assets_upsert(
    body: AssetUpsertRequest,
    auth: AuthContext = Depends(require_role("admin", "operator")),
):
    rows = p0_ops_service.upsert_assets(body.assets, source=body.source)
    p0_ops_service.append_audit(auth.token_fingerprint, auth.role, "asset_upsert", "p0/assets", {"count": len(rows)})
    return {"assets": [x.model_dump(mode="json") for x in rows]}


@router.get("/jobs")
def p0_jobs(_: AuthContext = Depends(require_role("admin", "operator", "viewer"))):
    return {"jobs": [x.model_dump(mode="json") for x in p0_ops_service.list_jobs()]}


@router.post("/jobs")
def p0_job_create(
    body: ScanJobCreateRequest,
    auth: AuthContext = Depends(require_role("admin", "operator")),
):
    job = p0_ops_service.create_job(body.name, body.targets, body.interval_minutes, enabled=body.enabled)
    p0_ops_service.append_audit(auth.token_fingerprint, auth.role, "job_create", f"p0/jobs/{job.job_id}")
    return job.model_dump(mode="json")


@router.post("/jobs/{job_id}/run")
async def p0_job_run(
    job_id: str,
    auth: AuthContext = Depends(require_role("admin", "operator")),
):
    try:
        summary = await p0_ops_service.run_job_once(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    p0_ops_service.append_audit(
        auth.token_fingerprint,
        auth.role,
        "job_run",
        f"p0/jobs/{job_id}",
        {"run_id": summary.run_id},
    )
    return summary.model_dump(mode="json")


@router.post("/scheduler/tick")
async def p0_scheduler_tick(auth: AuthContext = Depends(require_role("admin", "operator"))):
    rows = await p0_ops_service.run_due_jobs()
    p0_ops_service.append_audit(
        auth.token_fingerprint,
        auth.role,
        "scheduler_tick",
        "p0/scheduler",
        {"executed_jobs": len(rows)},
    )
    return {"executed": [x.model_dump(mode="json") for x in rows]}


@router.get("/runs")
def p0_runs(
    job_id: str | None = None,
    limit: int = 20,
    _: AuthContext = Depends(require_role("admin", "operator", "viewer")),
):
    return {"runs": p0_ops_service.list_runs(job_id=job_id, limit=max(1, min(200, limit)))}
