from __future__ import annotations

import re
from time import perf_counter

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.schemas.extraction_pipeline import (
    EvidencePack,
    ExtractionResult,
    StateNodeCandidate,
    TransitionCandidate,
)
from app.services.prompt_registry_service import prompt_registry

STATE_WORDS = [
    "register",
    "registered",
    "idle",
    "authenticated",
    "connected",
    "setup",
    "established",
    "terminated",
]


class WorkerExtractionService:
    async def run_worker(
        self,
        run_id: str,
        worker_name: str,
        evidence_pack: EvidencePack,
    ) -> ExtractionResult:
        start = perf_counter()
        mode = "conservative" if worker_name == "worker_a" else "structural"
        prompt_key = "worker_a_conservative" if worker_name == "worker_a" else "worker_b_structural"
        prompt = prompt_registry.get(prompt_key)
        llm_error: str | None = None
        states: list[StateNodeCandidate]
        transitions: list[TransitionCandidate]
        assumptions: list[str]
        open_questions: list[str]
        raw_response: dict
        engine = "fallback-rule"
        model_name = settings.extraction_worker_model if settings.llm_base_url else "fallback-local"
        token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        if settings.llm_provider and settings.llm_base_url:
            last_exc: Exception | None = None
            llm_result = None
            for _ in range(2):
                try:
                    llm_result = await self._run_worker_llm(
                        worker_name=worker_name,
                        evidence_pack=evidence_pack,
                        prompt_text=prompt.template,
                    )
                    break
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    continue
            if llm_result is not None:
                states = llm_result["states"]
                transitions = llm_result["transitions"]
                assumptions = llm_result["assumptions"]
                open_questions = llm_result["open_questions"]
                raw_response = llm_result["raw_response"]
                engine = "llm"
                model_name = llm_result["model_name"]
                token_usage = llm_result["token_usage"]
            else:
                llm_error = str(last_exc) if last_exc else "unknown llm error"
                states, transitions, assumptions, open_questions, raw_response = self._fallback_extract(
                    worker_name=worker_name,
                    evidence_pack=evidence_pack,
                )
        else:
            states, transitions, assumptions, open_questions, raw_response = self._fallback_extract(
                worker_name=worker_name,
                evidence_pack=evidence_pack,
            )

        if llm_error:
            assumptions.append(f"LLM fallback triggered: {llm_error[:180]}")

        elapsed_ms = int((perf_counter() - start) * 1000)
        return ExtractionResult(
            run_id=run_id,
            worker_name=worker_name,
            extraction_mode=mode,  # type: ignore[arg-type]
            states=states,
            transitions=transitions,
            entities=[],
            assumptions=assumptions,
            open_questions=open_questions,
            confidence_summary={
                "avg_state_conf": round(sum(s.confidence for s in states) / max(1, len(states)), 3),
                "avg_transition_conf": round(
                    sum(t.confidence for t in transitions) / max(1, len(transitions)),
                    3,
                ),
            },
            raw_response={"engine": engine, "worker_prompt": prompt.template, **raw_response},
            evidence_pack_id=evidence_pack.pack_id,
            prompt_version=prompt.version,
            model_name=model_name,
            timing_ms=elapsed_ms,
            token_usage=token_usage,
        )

    async def _run_worker_llm(
        self,
        worker_name: str,
        evidence_pack: EvidencePack,
        prompt_text: str,
    ) -> dict:
        provider = get_llm_provider()
        evidence_block = self._build_evidence_block(evidence_pack)
        user_prompt = (
            f"EvidencePack ID: {evidence_pack.pack_id}\n"
            f"Worker: {worker_name}\n"
            "Return STRICT JSON with keys:\n"
            "{states:[{temp_id,name,normalized_name,description,state_type,confidence,evidence_ids,attributes}],"
            "transitions:[{temp_id,from_state,to_state,trigger,guard,action,confidence,evidence_ids,attributes}],"
            "assumptions:[],open_questions:[]}\n\n"
            f"Evidence items:\n{evidence_block}"
        )
        llm = await provider.chat_json(
            system_prompt=prompt_text,
            user_prompt=user_prompt,
            model_name=settings.extraction_worker_model,
            temperature=0.1 if worker_name == "worker_a" else 0.25,
        )
        raw = llm.raw or {}
        states = [StateNodeCandidate.model_validate(self._sanitize_state(s)) for s in (raw.get("states") or [])]
        transitions = [
            TransitionCandidate.model_validate(self._sanitize_transition(t))
            for t in (raw.get("transitions") or [])
        ]
        assumptions = [str(x) for x in (raw.get("assumptions") or [])]
        open_questions = [str(x) for x in (raw.get("open_questions") or [])]
        if not states:
            raise ValueError("worker llm returned empty states")
        return {
            "states": states,
            "transitions": transitions,
            "assumptions": assumptions,
            "open_questions": open_questions,
            "raw_response": {"llm_raw": raw},
            "model_name": llm.model or settings.extraction_worker_model,
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    def _fallback_extract(self, worker_name: str, evidence_pack: EvidencePack) -> tuple:
        states = self._extract_states(evidence_pack, conservative=(worker_name == "worker_a"))
        transitions = self._build_transitions(states, evidence_pack, conservative=(worker_name == "worker_a"))
        assumptions: list[str] = []
        if worker_name == "worker_b" and len(states) <= 1 and evidence_pack.items:
            assumptions.append("Structural completion applied due to sparse explicit state markers.")
        open_questions = self._open_questions(states, transitions)
        return states, transitions, assumptions, open_questions, {}

    def _build_evidence_block(self, pack: EvidencePack) -> str:
        lines: list[str] = []
        for item in pack.items:
            snippet = item.text.replace("\n", " ")[:260]
            lines.append(
                f"- {item.evidence_id} | heading={item.heading or '-'} | score={item.relevance_score} | text={snippet}"
            )
        return "\n".join(lines)

    def _sanitize_state(self, value: dict) -> dict:
        return {
            "temp_id": str(value.get("temp_id") or f"st_{abs(hash(str(value))) % 9999:04d}"),
            "name": str(value.get("name") or "UnknownState"),
            "normalized_name": str(value.get("normalized_name") or value.get("name") or "unknown_state").lower().replace(" ", "_"),
            "description": str(value.get("description") or ""),
            "state_type": str(value.get("state_type") or "State"),
            "confidence": float(value.get("confidence") if value.get("confidence") is not None else 0.6),
            "evidence_ids": [str(x) for x in (value.get("evidence_ids") or [])],
            "attributes": value.get("attributes") or {},
        }

    def _sanitize_transition(self, value: dict) -> dict:
        return {
            "temp_id": str(value.get("temp_id") or f"tr_{abs(hash(str(value))) % 9999:04d}"),
            "from_state": str(value.get("from_state") or ""),
            "to_state": str(value.get("to_state") or ""),
            "trigger": str(value.get("trigger") or "state_transition"),
            "guard": str(value.get("guard") or ""),
            "action": str(value.get("action") or ""),
            "confidence": float(value.get("confidence") if value.get("confidence") is not None else 0.6),
            "evidence_ids": [str(x) for x in (value.get("evidence_ids") or [])],
            "attributes": value.get("attributes") or {},
        }

    def _extract_states(self, pack: EvidencePack, conservative: bool) -> list[StateNodeCandidate]:
        states: dict[str, StateNodeCandidate] = {}
        for item in pack.items:
            words = re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,32}", item.text)
            for w in words:
                lw = w.lower()
                if lw in STATE_WORDS or lw.endswith("ed") or lw.endswith("ing"):
                    key = lw
                    if key not in states:
                        states[key] = StateNodeCandidate(
                            temp_id=f"st_{len(states)+1:03d}",
                            name=w,
                            normalized_name=lw.replace("-", "_"),
                            description=f"State candidate from evidence '{item.heading or item.chunk_id}'.",
                            confidence=0.82 if conservative else 0.74,
                            evidence_ids=[item.evidence_id],
                        )
                    elif item.evidence_id not in states[key].evidence_ids:
                        states[key].evidence_ids.append(item.evidence_id)
        if not states and pack.items:
            first = pack.items[0]
            states["init"] = StateNodeCandidate(
                temp_id="st_001",
                name="Init",
                normalized_name="init",
                description="Fallback initial state from first evidence item.",
                confidence=0.6,
                evidence_ids=[first.evidence_id],
            )
        return list(states.values())[: (8 if conservative else 12)]

    def _build_transitions(
        self,
        states: list[StateNodeCandidate],
        pack: EvidencePack,
        conservative: bool,
    ) -> list[TransitionCandidate]:
        if len(states) <= 1:
            return []
        transitions: list[TransitionCandidate] = []
        for idx in range(len(states) - 1):
            from_state = states[idx]
            to_state = states[idx + 1]
            transitions.append(
                TransitionCandidate(
                    temp_id=f"tr_{idx+1:03d}",
                    from_state=from_state.temp_id,
                    to_state=to_state.temp_id,
                    trigger="protocol_message" if conservative else "inferred_progression",
                    guard="evidence_grounded",
                    action="state_update",
                    confidence=0.76 if conservative else 0.7,
                    evidence_ids=list({*from_state.evidence_ids, *to_state.evidence_ids})[:2],
                )
            )
        if not conservative and len(states) >= 2 and pack.items:
            # structural worker may add loopback completion edge
            transitions.append(
                TransitionCandidate(
                    temp_id=f"tr_{len(transitions)+1:03d}",
                    from_state=states[-1].temp_id,
                    to_state=states[0].temp_id,
                    trigger="session_reset",
                    guard="optional",
                    action="loopback",
                    confidence=0.55,
                    evidence_ids=[pack.items[-1].evidence_id],
                    attributes={"inferred": True},
                )
            )
        return transitions

    def _open_questions(
        self,
        states: list[StateNodeCandidate],
        transitions: list[TransitionCandidate],
    ) -> list[str]:
        questions: list[str] = []
        if len(states) < 2:
            questions.append("State count is low; provide richer section snippets if available.")
        if not transitions:
            questions.append("No transition confidently extracted from current evidence pack.")
        return questions


worker_extraction_service = WorkerExtractionService()

