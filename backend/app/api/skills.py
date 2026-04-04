from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.skills.registry import registry

router = APIRouter(tags=["skills"])


@router.get("/skills")
def list_skills():
    return {"skills": registry.list_tools()}


@router.post("/skills/run")
async def run_skill(body: dict):
    name = body.get("name")
    args = body.get("input") or {}
    meta_func = registry.get(name)
    if not meta_func:
        raise HTTPException(status_code=404, detail=f"skill {name!r} not found")
    meta, func = meta_func
    res = func(args)
    if hasattr(res, "__await__"):
        res = await res  # type: ignore[assignment]
    return {"skill": meta.name, "output": res}

