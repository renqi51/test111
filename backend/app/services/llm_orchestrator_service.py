from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.core.config import settings
from app.schemas.extraction_pipeline import (
    ExtractionRunRequest,
    ExtractionRunResponse,
    ExtractionStatusResponse,
    JudgeDecision,
    RepairedExtractionResult,
)
from app.services.chunking_service import chunking_service
from app.services.document_ingest_service import document_ingest_service
from app.services.evidence_pack_service import evidence_pack_service
from app.services.extraction_audit_service import extraction_audit_service
from app.services.judge_service import judge_service
from app.services.prompt_registry_service import prompt_registry
from app.services.repair_service import repair_service
from app.services.staging_graph_service import staging_graph_service
from app.services.trace_service import trace_service
from app.services.worker_extraction_service import worker_extraction_service
from app.repositories.graph_repository import get_graph_repository
from app.services.retrieval_service import retrieval_service


class LLMOrchestratorService:
    async def run(self, req: ExtractionRunRequest) -> ExtractionRunResponse:
        run_id = f"run_{uuid4().hex[:10]}"
        traces: list[dict] = []

        t0 = trace_service.begin("stage0_input")
        doc_input = document_ingest_service.build_input(
            text=req.text,
            title=req.title,
            source_type=req.source_type,
            metadata=req.metadata,
        )
        traces.append(
            trace_service.end(
                t0,
                {"document_id": doc_input.document_id, "source_type": doc_input.source_type},
            ).__dict__
        )

        t1 = trace_service.begin("stage1_preprocess")
        chunks = chunking_service.chunk_document(doc_input)
        traces.append(trace_service.end(t1, {"chunk_count": len(chunks)}).__dict__)

        t2 = trace_service.begin("stage2_retrieval")
        top_k = settings.extraction_evidence_top_k
        if req.budget_mode == "high_precision" or req.high_precision:
            top_k = min(settings.extraction_evidence_top_k_high_precision, max(top_k, 12))
        retrieval_strategy = str(
            req.retrieval_strategy
            or req.metadata.get("retrieval_strategy")
            or settings.extraction_retrieval_strategy
        )
        rerank_used = bool(
            req.rerank_used
            if req.rerank_used is not None
            else req.metadata.get("rerank_used", settings.extraction_rerank_enabled)
        )
        rerank_strategy = str(
            req.rerank_strategy
            or req.metadata.get("rerank_strategy")
            or settings.extraction_rerank_strategy
        )
        evidence_pack = evidence_pack_service.build(
            chunks=chunks,
            query=self._build_retrieval_query(
                title=doc_input.title,
                scenario_hint=req.scenario_hint,
                raw_text=doc_input.raw_text,
            ),
            scenario_hint=req.scenario_hint,
            top_k=top_k,
            strategy=retrieval_strategy,
            rerank_used=rerank_used,
            rerank_strategy=rerank_strategy,
        )
        traces.append(
            trace_service.end(
                t2,
                {"evidence_pack_id": evidence_pack.pack_id, "items": len(evidence_pack.items)},
            ).__dict__
        )
        trace_service.save_evidence_pack(run_id, evidence_pack.model_dump())

        t3 = trace_service.begin("stage3_workers")
        worker_names = ["worker_a", "worker_b"]
        worker_tasks = [
            worker_extraction_service.run_worker(run_id=run_id, worker_name=w, evidence_pack=evidence_pack)
            for w in worker_names
        ]
        workers = await asyncio.gather(*worker_tasks)
        traces.append(trace_service.end(t3, {"workers": [w.worker_name for w in workers]}).__dict__)

        t4 = trace_service.begin("stage4_judge")
        judge = await judge_service.evaluate(
            evidence_pack=evidence_pack,
            workers=workers,
            low_score_threshold=settings.extraction_low_score_threshold,
            conflict_threshold=settings.extraction_conflict_threshold,
        )
        traces.append(
            trace_service.end(
                t4,
                {
                    "recommended_worker": judge.recommended_worker,
                    "needs_repair": judge.needs_repair,
                    "conflicts": len(judge.conflict_set),
                },
            ).__dict__
        )

        repair: RepairedExtractionResult | None = None
        selected = self._select_result(workers, judge)
        if judge.needs_repair and settings.extraction_enable_repair:
            t5 = trace_service.begin("stage5_repair")
            repair = repair_service.repair(
                run_id=run_id,
                preferred_result=selected,
                conflicts=judge.conflict_set,
                judge=judge,
            )
            selected = repair.extraction_result
            traces.append(
                trace_service.end(
                    t5,
                    {"updated_fields": repair.updated_fields, "unresolved": len(repair.unresolved_conflicts)},
                ).__dict__
            )

        audit = extraction_audit_service.audit(selected)
        t6 = trace_service.begin("stage6_staging_graph")
        staging = staging_graph_service.build(
            run_id=run_id,
            document_id=doc_input.document_id,
            extraction=selected,
            judge=judge,
        )
        traces.append(
            trace_service.end(
                t6,
                {
                    "staging_nodes": len(staging.nodes),
                    "staging_edges": len(staging.edges),
                    "audit_ok": audit.get("ok", False),
                },
            ).__dict__
        )
        repo = get_graph_repository()
        repo.save_staging_graph(run_id, staging.model_dump())

        report_md = self._build_report_markdown(run_id, req, evidence_pack, workers, judge, repair, audit, staging)
        report_path = trace_service.save_report(run_id, report_md)
        prompt_meta = {
            "worker_a": prompt_registry.get_metadata("worker_a_conservative"),
            "worker_b": prompt_registry.get_metadata("worker_b_structural"),
            "judge": prompt_registry.get_metadata("judge_scoring"),
            "repair": prompt_registry.get_metadata("repair_conflicts"),
        }
        run_meta = {
            "prompt_versions": {k: v["version"] for k, v in prompt_meta.items()},
            "prompt_hashes": {k: v["hash"] for k, v in prompt_meta.items()},
            "retrieval_strategy": evidence_pack.retrieval_strategy,
            "retrieval_version": evidence_pack.retrieval_version,
            "rerank_used": evidence_pack.rerank_used,
            "rerank_strategy": evidence_pack.rerank_strategy,
        }

        run_payload = {
            "run_id": run_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "request": req.model_dump(),
            "document_input": doc_input.model_dump(),
            "evidence_pack": evidence_pack.model_dump(),
            "worker_results": [w.model_dump() for w in workers],
            "judge": judge.model_dump(),
            "repair": repair.model_dump() if repair else None,
            "staging_graph": staging.model_dump(),
            "audit": audit,
            "report_path": str(report_path),
            "run_meta": run_meta,
            "trace_summary": {
                "stage_count": len(traces),
                "total_timing_ms": sum(w.timing_ms for w in workers) + judge.timing_ms,
            },
        }
        trace_service.save_run(run_id, run_payload)
        trace_service.save_trace(run_id, traces)

        return ExtractionRunResponse(
            run_id=run_id,
            stage="stage8_report_ready",
            evidence_pack=evidence_pack,
            worker_results=workers,
            judge=judge,
            repair=repair,
            staging_graph_summary={
                "node_count": len(staging.nodes),
                "edge_count": len(staging.edges),
                "status": "pending_human_review",
            },
            trace_summary=run_payload["trace_summary"],
            run_meta=run_meta,
        )

    def _select_result(self, workers, judge: JudgeDecision):
        for w in workers:
            if w.worker_name == judge.recommended_worker:
                return w
        return workers[0]

    def _build_report_markdown(self, run_id, req, evidence_pack, workers, judge, repair, audit, staging) -> str:
        return (
            f"# Extraction Run Report: {run_id}\n\n"
            f"- Scenario: {req.scenario_hint}\n"
            f"- Budget mode: {req.budget_mode}\n"
            f"- Evidence items: {len(evidence_pack.items)}\n"
            f"- Workers: {', '.join([w.worker_name for w in workers])}\n"
            f"- Recommended worker: {judge.recommended_worker}\n"
            f"- Needs repair: {judge.needs_repair}\n"
            f"- Repair applied: {'yes' if repair else 'no'}\n"
            f"- Staging nodes/edges: {len(staging.nodes)}/{len(staging.edges)}\n"
            f"- Audit ok: {audit.get('ok', False)}\n\n"
            "## Safety Notice\n"
            "Probe features are restricted to authorized lab environments only.\n"
            "This system does not include unauthorized scanning.\n"
        )

    def _build_retrieval_query(self, title: str, scenario_hint: str, raw_text: str) -> str:
        snippet = " ".join(raw_text.split())[:300]
        return f"{title or ''} {scenario_hint or ''} {snippet}".strip()

    def get_status(self) -> ExtractionStatusResponse:
        latest_run_id = trace_service.latest_run_id()
        latest_summary = None
        if latest_run_id:
            payload = trace_service.load_run(latest_run_id) or {}
            latest_summary = {
                "run_id": latest_run_id,
                "recommended_worker": payload.get("judge", {}).get("recommended_worker"),
                "needs_repair": payload.get("judge", {}).get("needs_repair"),
            }
        return ExtractionStatusResponse(
            llm={
                "enabled": bool(settings.llm_provider and settings.llm_base_url),
                "provider": settings.llm_provider,
                "model_worker": settings.extraction_worker_model,
                "model_judge": settings.extraction_judge_model,
            },
            retrieval={
                "enabled": True,
                "strategy": settings.extraction_retrieval_strategy,
                "available_strategies": retrieval_service.list_retrievers(),
                "evidence_top_k": settings.extraction_evidence_top_k,
                "rerank_enabled": settings.extraction_rerank_enabled,
                "rerank_strategy": settings.extraction_rerank_strategy,
            },
            graph={
                "staging_backend": settings.extraction_staging_backend,
                "main_backend": settings.graph_backend,
            },
            budget={
                "default_workers": 2,
                "default_judges": 1,
                "max_repairs": settings.extraction_max_repair_rounds,
                "high_precision_enabled": True,
            },
            latest=latest_summary,
            latest_run_id=latest_run_id,
        )

    def get_prompts(self) -> dict:
        return {"prompts": prompt_registry.list_versions()}


llm_orchestrator_service = LLMOrchestratorService()

