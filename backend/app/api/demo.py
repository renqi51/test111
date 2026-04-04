from fastapi import APIRouter

from app.services.report_service import build_demo_summary_md

router = APIRouter(tags=["demo"])


@router.get("/demo/summary")
def demo_summary():
    """JSON wrapper so SPA can render Markdown in-page."""
    return {"markdown": build_demo_summary_md()}
