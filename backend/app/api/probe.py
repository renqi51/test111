from fastapi import APIRouter, HTTPException

from app.schemas.probe import ProbeRunRequest, ProbeRunResponse, ProbeStatusPayload
from app.services import probe_service

router = APIRouter(tags=["probe"])


@router.get("/probe/status", response_model=ProbeStatusPayload)
def probe_status():
    return probe_service.probe_status()


@router.get("/probe/last")
def probe_last():
    last = probe_service.get_last_run()
    if not last:
        return {"run": None}
    return {"run": last}


@router.post("/probe/run", response_model=ProbeRunResponse)
async def probe_run(body: ProbeRunRequest):
    try:
        return await probe_service.run_probe(body)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
