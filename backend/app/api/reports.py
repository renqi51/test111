from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.services.report_service import build_demo_summary_md, build_mermaid, build_validation_markdown

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/validation")
def report_validation():
    return PlainTextResponse(build_validation_markdown(), media_type="text/markdown; charset=utf-8")


@router.get("/mermaid")
def report_mermaid():
    return PlainTextResponse(build_mermaid(), media_type="text/plain; charset=utf-8")


@router.get("/demo_summary_md")
def report_demo_summary():
    return PlainTextResponse(build_demo_summary_md(), media_type="text/markdown; charset=utf-8")
