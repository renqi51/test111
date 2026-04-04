"""Mock experiment tasks — no real scanning."""
from fastapi import APIRouter

from app.core.config import SEED_DIR
import json
router = APIRouter(tags=["experiments"])


@router.get("/experiments")
def list_experiments():
    p = SEED_DIR / "experiments.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    return data
