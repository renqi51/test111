from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.utils.storage import init_runtime_from_seed_if_missing
from app.api import graph, extract, extraction, exposure, reports, demo, experiments, skills, agent, mcp, probe, builder, graph_rag
from app.repositories.graph_repository import get_graph_repository

app = FastAPI(title=settings.app_name, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    # 仍然初始化本地 seed/runtime，作为 Neo4j 不可用时的 fallback
    init_runtime_from_seed_if_missing()
    # 触发仓储初始化（包括 Neo4j 连接尝试）
    _ = get_graph_repository()


app.include_router(graph.router, prefix="/api")
app.include_router(extract.router, prefix="/api")
app.include_router(extraction.router, prefix="/api")
app.include_router(exposure.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(demo.router, prefix="/api")
app.include_router(experiments.router, prefix="/api")
app.include_router(skills.router, prefix="/api")
app.include_router(agent.router, prefix="/api")
app.include_router(mcp.router, prefix="/api")
app.include_router(probe.router, prefix="/api")
app.include_router(builder.router, prefix="/api")
app.include_router(graph_rag.router, prefix="/api")


@app.get("/api/system/status")
def system_status():
    # 简化版：前端用来显示 Neo4j / LLM / Agent 状态
    graph_backend = settings.graph_backend
    llm_enabled = settings.llm_enabled
    neo4j_ok = False
    if graph_backend == "neo4j":
        try:
            repo = get_graph_repository()
            # If repository is neo4j-backed, count a tiny query.
            if repo.__class__.__name__.startswith("Neo4j"):
                g = repo.get_graph()
                _ = (len(g.get("nodes", [])), len(g.get("edges", [])))
                neo4j_ok = True
        except Exception:  # noqa: BLE001
            neo4j_ok = False
    return {
        "graph_backend": graph_backend,
        "neo4j": {
            "enabled": graph_backend == "neo4j",
            "ok": neo4j_ok,
            "uri": settings.neo4j_uri if graph_backend == "neo4j" else None,
        },
        "llm": {
            "provider": settings.llm_provider,
            "model": settings.llm_model_name if llm_enabled else None,
            "enabled": llm_enabled,
        },
        "agent": {"enabled": True},
        "extraction": {
            "enabled": True,
            "budget_mode": settings.extraction_budget_mode,
            "worker_model": settings.extraction_worker_model,
            "judge_model": settings.extraction_judge_model,
            "evidence_top_k": settings.extraction_evidence_top_k,
            "repair_enabled": settings.extraction_enable_repair,
            "staging_backend": settings.extraction_staging_backend,
        },
        "probe": {
            "enabled": settings.probe_enabled,
            "mode": settings.probe_mode,
            "allowlist_configured": bool((settings.probe_allowlist_suffixes or "").strip()),
        },
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
