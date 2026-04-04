from __future__ import annotations

from time import perf_counter
from uuid import uuid4

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.schemas.extraction_pipeline import (
    ConflictItem,
    EvidencePack,
    ExtractionResult,
    JudgeDecision,
    JudgeScoreDetail,
)
from app.services.prompt_registry_service import prompt_registry


class JudgeService:
    async def evaluate(
        self,
        evidence_pack: EvidencePack,
        workers: list[ExtractionResult],
        low_score_threshold: float = 0.65,
        conflict_threshold: int = 3,
    ) -> JudgeDecision:
        start = perf_counter()
        prompt = prompt_registry.get("judge_scoring")
        llm_error: str | None = None
        retry_reason = ""
        validation_errors: list[str] = []
        normalization_notes: list[str] = []
        details: list[JudgeScoreDetail]
        conflicts: list[ConflictItem]
        recommended: str
        token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        model_name = settings.extraction_judge_model if settings.llm_base_url else "fallback-local"

        if settings.llm_provider and settings.llm_base_url:
            network_retries = 0
            semantic_retries = 0
            while True:
                try:
                    llm_eval = await self._evaluate_with_llm(evidence_pack, workers, prompt.template)
                    details = llm_eval["details"]
                    conflicts = llm_eval["conflicts"]
                    recommended = llm_eval["recommended"]
                    model_name = llm_eval["model_name"]
                    token_usage = llm_eval["token_usage"]
                    normalization_notes = llm_eval["normalization_notes"]
                    validation_errors = llm_eval["validation_errors"]
                    break
                except Exception as exc:  # noqa: BLE001
                    llm_error = str(exc)
                    if self._is_network_error(llm_error) and network_retries < 2:
                        network_retries += 1
                        retry_reason = f"network_retry:{network_retries}"
                        continue
                    if self._is_semantic_error(llm_error) and semantic_retries < 1:
                        semantic_retries += 1
                        retry_reason = f"semantic_retry:{semantic_retries}"
                        continue
                    details = self._evaluate_fallback_details(evidence_pack, workers)
                    conflicts = self._build_conflicts(workers)
                    recommended = max(details, key=lambda x: x.total_score).worker_name if details else ""
                    if not retry_reason:
                        retry_reason = "fallback_no_retry"
                    break
        else:
            details = self._evaluate_fallback_details(evidence_pack, workers)
            conflicts = self._build_conflicts(workers)
            recommended = max(details, key=lambda x: x.total_score).worker_name if details else ""

        best_score = max([d.total_score for d in details], default=0.0)
        needs_repair = best_score < low_score_threshold or len(conflicts) >= conflict_threshold

        elapsed_ms = int((perf_counter() - start) * 1000)
        comments = [f"LLM fallback triggered: {llm_error[:160]}"] if llm_error else []
        if comments and details:
            details[0].comments.extend(comments)
        return JudgeDecision(
            judge_run_id=f"judge_{uuid4().hex[:10]}",
            score_details=details,
            recommended_worker=recommended,
            recommended_merge_strategy="prefer_recommended_worker_if_conflict",
            conflict_set=conflicts,
            needs_repair=needs_repair,
            repair_instruction=(
                "Repair only conflict_set field paths; do not rerun complete extraction."
                if needs_repair
                else ""
            ),
            prompt_version=prompt.version,
            model_name=model_name,
            timing_ms=elapsed_ms,
            token_usage=token_usage,
            normalization_notes=normalization_notes,
            validation_errors=validation_errors,
            retry_reason=retry_reason,
            fallback_reason=(llm_error[:220] if llm_error else ""),
        )

    async def _evaluate_with_llm(self, evidence_pack: EvidencePack, workers: list[ExtractionResult], prompt_text: str) -> dict:
        provider = get_llm_provider()
        worker_payload = []
        for w in workers:
            worker_payload.append(
                {
                    "worker_name": w.worker_name,
                    "state_count": len(w.states),
                    "transition_count": len(w.transitions),
                    "state_names": [s.normalized_name for s in w.states[:8]],
                    "transition_pairs": [f"{t.from_state}->{t.to_state}:{t.trigger}" for t in w.transitions[:10]],
                    "assumptions": w.assumptions[:3],
                }
            )
        user_prompt = (
            "Evidence-grounded judge task.\n"
            "Return STRICT JSON with keys:\n"
            "{score_details:[{worker_name,schema_validity_score,evidence_alignment_score,graph_consistency_score,"
            "completeness_score,conservativeness_score,total_score,comments}],"
            "recommended_worker,recommended_merge_strategy,conflict_set:[{field_path,conflict_type,description,"
            "candidate_values,related_evidence_ids,severity}],needs_repair,repair_instruction}\n\n"
            f"Evidence pack summary: id={evidence_pack.pack_id}, items={len(evidence_pack.items)}\n"
            f"Worker payload: {worker_payload}"
        )
        llm = await provider.chat_json(
            system_prompt=prompt_text,
            user_prompt=user_prompt,
            model_name=settings.extraction_judge_model,
            temperature=0.1,
        )
        raw = llm.raw or {}
        normalization_notes: list[str] = []
        validation_errors: list[str] = []
        details = [
            JudgeScoreDetail.model_validate(self._sanitize_score_detail(x, normalization_notes, validation_errors))
            for x in (raw.get("score_details") or [])
        ]
        conflicts = [
            ConflictItem.model_validate(self._sanitize_conflict(x, normalization_notes, validation_errors))
            for x in (raw.get("conflict_set") or [])
        ]
        if not details:
            raise ValueError("judge llm returned empty score_details")
        recommended = str(raw.get("recommended_worker") or (details[0].worker_name if details else ""))
        return {
            "details": details,
            "conflicts": conflicts,
            "recommended": recommended,
            "model_name": llm.model or settings.extraction_judge_model,
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "normalization_notes": normalization_notes,
            "validation_errors": validation_errors,
        }

    def _sanitize_score_detail(self, value: dict, notes: list[str], errors: list[str]) -> dict:
        if not isinstance(value, dict):
            errors.append("score_detail_not_object")
            value = {}

        def _s(v: float) -> float:
            try:
                sv = float(v)
            except Exception:  # noqa: BLE001
                errors.append(f"score_type_error:{v!r}")
                return 0.0
            clamped = max(0.0, min(1.0, sv))
            if clamped != sv:
                notes.append(f"score_clamped:{sv}->{clamped}")
            return clamped

        return {
            "worker_name": str(value.get("worker_name") or "worker_a"),
            "schema_validity_score": _s(value.get("schema_validity_score") if value.get("schema_validity_score") is not None else 0.0),
            "evidence_alignment_score": _s(value.get("evidence_alignment_score") if value.get("evidence_alignment_score") is not None else 0.0),
            "graph_consistency_score": _s(value.get("graph_consistency_score") if value.get("graph_consistency_score") is not None else 0.0),
            "completeness_score": _s(value.get("completeness_score") if value.get("completeness_score") is not None else 0.0),
            "conservativeness_score": _s(value.get("conservativeness_score") if value.get("conservativeness_score") is not None else 0.0),
            "total_score": _s(value.get("total_score") if value.get("total_score") is not None else 0.0),
            "comments": [str(x) for x in (value.get("comments") or [])],
        }

    def _sanitize_conflict(self, value: dict, notes: list[str], errors: list[str]) -> dict:
        if not isinstance(value, dict):
            errors.append("conflict_not_object")
            value = {}
        severity = str(value.get("severity") or "medium").lower()
        if severity not in {"low", "medium", "high"}:
            notes.append(f"conflict_severity_normalized:{severity}->medium")
            severity = "medium"
        candidate_values = value.get("candidate_values")
        if not isinstance(candidate_values, dict):
            errors.append("conflict_candidate_values_not_dict")
            candidate_values = {"raw": candidate_values}
        return {
            "field_path": str(value.get("field_path") or "unknown"),
            "conflict_type": str(value.get("conflict_type") or "unknown"),
            "description": str(value.get("description") or ""),
            "candidate_values": candidate_values or {},
            "related_evidence_ids": [str(x) for x in (value.get("related_evidence_ids") or [])],
            "severity": severity,
        }

    def _is_network_error(self, text: str) -> bool:
        t = text.lower()
        return any(
            marker in t
            for marker in [
                "timeout",
                "timed out",
                "server disconnected",
                "connection",
                "gateway",
                "httpstatuserror",
                "502",
                "503",
                "504",
            ]
        )

    def _is_semantic_error(self, text: str) -> bool:
        t = text.lower()
        return any(
            marker in t
            for marker in [
                "validation",
                "json",
                "score_details",
                "schema",
                "missing",
                "type",
            ]
        )

    def _evaluate_fallback_details(self, evidence_pack: EvidencePack, workers: list[ExtractionResult]) -> list[JudgeScoreDetail]:
        details: list[JudgeScoreDetail] = []
        for w in workers:
            schema = 1.0 if w.states is not None and w.transitions is not None else 0.0
            aligned = self._evidence_alignment(w, evidence_pack)
            consistency = self._graph_consistency(w)
            completeness = min(1.0, (len(w.states) / 6.0) + (len(w.transitions) / 8.0))
            conservative = 1.0 - self._inference_ratio(w)
            total = round(
                0.22 * schema
                + 0.27 * aligned
                + 0.2 * consistency
                + 0.18 * completeness
                + 0.13 * conservative,
                4,
            )
            details.append(
                JudgeScoreDetail(
                    worker_name=w.worker_name,
                    schema_validity_score=round(schema, 4),
                    evidence_alignment_score=round(aligned, 4),
                    graph_consistency_score=round(consistency, 4),
                    completeness_score=round(completeness, 4),
                    conservativeness_score=round(conservative, 4),
                    total_score=total,
                    comments=[],
                )
            )
        return details

    def _evidence_alignment(self, result: ExtractionResult, pack: EvidencePack) -> float:
        evidence_ids = {e.evidence_id for e in pack.items}
        hit = 0
        total = 0
        for s in result.states:
            total += 1
            if any(eid in evidence_ids for eid in s.evidence_ids):
                hit += 1
        for t in result.transitions:
            total += 1
            if any(eid in evidence_ids for eid in t.evidence_ids):
                hit += 1
        return hit / max(1, total)

    def _graph_consistency(self, result: ExtractionResult) -> float:
        ids = {s.temp_id for s in result.states}
        if not result.transitions:
            return 0.75 if len(ids) > 0 else 0.2
        valid = 0
        for t in result.transitions:
            if t.from_state in ids and t.to_state in ids:
                valid += 1
        return valid / max(1, len(result.transitions))

    def _inference_ratio(self, result: ExtractionResult) -> float:
        inferred = 0
        total = 0
        for t in result.transitions:
            total += 1
            if t.attributes.get("inferred"):
                inferred += 1
        return inferred / max(1, total)

    def _build_conflicts(self, workers: list[ExtractionResult]) -> list[ConflictItem]:
        if len(workers) < 2:
            return []
        wa, wb = workers[0], workers[1]
        conflicts: list[ConflictItem] = []
        if len(wa.states) != len(wb.states):
            conflicts.append(
                ConflictItem(
                    field_path="states.length",
                    conflict_type="count_mismatch",
                    description="Worker state count mismatch.",
                    candidate_values={wa.worker_name: len(wa.states), wb.worker_name: len(wb.states)},
                    severity="medium",
                )
            )
        if len(wa.transitions) != len(wb.transitions):
            conflicts.append(
                ConflictItem(
                    field_path="transitions.length",
                    conflict_type="count_mismatch",
                    description="Worker transition count mismatch.",
                    candidate_values={
                        wa.worker_name: len(wa.transitions),
                        wb.worker_name: len(wb.transitions),
                    },
                    severity="medium",
                )
            )
        a_names = {s.normalized_name for s in wa.states}
        b_names = {s.normalized_name for s in wb.states}
        if a_names != b_names:
            conflicts.append(
                ConflictItem(
                    field_path="states.names",
                    conflict_type="set_mismatch",
                    description="Extracted state name sets differ.",
                    candidate_values={
                        wa.worker_name: sorted(a_names),
                        wb.worker_name: sorted(b_names),
                    },
                    severity="high",
                )
            )
        return conflicts


judge_service = JudgeService()

