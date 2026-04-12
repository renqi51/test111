from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.schemas.exposure import (
    ExposureAnalysisResponse,
    ExposureAnalyzeRequest,
    ExposureGenerateRequest,
    ExposureRow,
)
from app.services.exposure_service import analyze_exposure, generate_probe_backed_rows, load_exposure_analysis
import csv
import io

router = APIRouter(tags=["exposure"])


@router.post("/exposure/generate", response_model=list[ExposureRow])
async def exposure_generate(body: ExposureGenerateRequest):
    rows, _ = await generate_probe_backed_rows(
        service=body.service,
        domains=body.domains,
        ips=body.ips,
        cidrs=body.cidrs,
        extra_hosts=None,
        include_probe=body.include_probe,
    )
    return [ExposureRow.model_validate(r) for r in rows]


@router.post("/exposure/export_csv")
async def exposure_export_csv(body: ExposureGenerateRequest):
    rows, _ = await generate_probe_backed_rows(
        service=body.service,
        domains=body.domains,
        ips=body.ips,
        cidrs=body.cidrs,
        extra_hosts=None,
        include_probe=body.include_probe,
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        ["candidate_fqdn", "protocol_stack", "network_functions", "evidence_docs", "risk_hypotheses", "confidence"]
    )
    for r in rows:
        w.writerow(
            [
                r["candidate_fqdn"],
                "|".join(r["protocol_stack"]),
                "|".join(r["network_functions"]),
                "|".join(r["evidence_docs"]),
                "|".join(r["risk_hypotheses"]),
                r["confidence"],
            ]
        )
    return PlainTextResponse(buf.getvalue(), media_type="text/csv; charset=utf-8")


@router.post("/exposure/analyze", response_model=ExposureAnalysisResponse)
async def exposure_analyze(body: ExposureAnalyzeRequest):
    return await analyze_exposure(
        service=body.service,
        mcc=body.mcc,
        mnc=body.mnc,
        domains=body.domains,
        ips=body.ips,
        cidrs=body.cidrs,
        include_probe=body.include_probe,
        extra_hosts=body.extra_hosts,
        use_llm=body.use_llm,
    )


@router.get("/exposure/{run_id}", response_model=ExposureAnalysisResponse)
def exposure_get_run(run_id: str):
    payload = load_exposure_analysis(run_id)
    if payload is None:
        return ExposureAnalysisResponse(
            run_id=run_id,
            service="",
            mcc="000",
            mnc="00",
            summary={"error": "run not found"},
        )
    return payload


@router.get("/exposure/{run_id}/report")
def exposure_get_report(run_id: str):
    payload = load_exposure_analysis(run_id)
    if payload is None or not payload.report_path:
        return PlainTextResponse("report not found", status_code=404)
    try:
        with open(payload.report_path, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read(), media_type="text/markdown; charset=utf-8")
    except OSError:
        return PlainTextResponse("report not found", status_code=404)
