from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from app.core.config import settings


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    version: str
    template: str
    source: str = "builtin"


class PromptRegistryService:
    def __init__(self) -> None:
        self._prompts: dict[str, PromptTemplate] = {
            "retrieval_query_expansion": PromptTemplate(
                name="retrieval_query_expansion",
                version="v1",
                template=(
                    "You are expanding telecom standard retrieval queries.\n"
                    "Return 3 short keyword variants related to 3GPP/IMS/VoWiFi/Open Gateway."
                ),
            ),
            "worker_a_conservative": PromptTemplate(
                name="worker_a_conservative",
                version="v1",
                template=(
                    "You are Worker A (conservative extraction).\n"
                    "Extract only evidence-grounded states/transitions from evidence pack.\n"
                    "Every state/transition must carry evidence_ids.\n"
                    "Output JSON with fields: states, transitions, assumptions, open_questions."
                ),
            ),
            "worker_b_structural": PromptTemplate(
                name="worker_b_structural",
                version="v1",
                template=(
                    "You are Worker B (structural induction).\n"
                    "Use the same evidence pack to produce a more complete state machine.\n"
                    "Do not hallucinate: inferred items must still attach evidence_ids and uncertainty notes.\n"
                    "Output JSON with fields: states, transitions, assumptions, open_questions."
                ),
            ),
            "judge_scoring": PromptTemplate(
                name="judge_scoring",
                version="v1",
                template=(
                    """
                        You are the final adjudication engine for a telecom/security-oriented structured extraction pipeline.

                        Your job is NOT to rewrite the candidate freely.
                        Your job is to evaluate whether the candidate extraction is strictly supported by the provided evidence pack and whether it is internally consistent with the graph/context snapshot.

                        You must behave like a conservative enterprise-grade validation component used in a production data pipeline.

                        ========================
                        PRIMARY RESPONSIBILITIES
                        ========================
                        1. Validate whether each extracted field is supported by explicit evidence.
                        2. Detect unsupported inference, overclaiming, hallucination, contradiction, and schema misuse.
                        3. Score the candidate across required dimensions.
                        4. Produce a machine-readable adjudication result.
                        5. Recommend repair actions when the candidate is incomplete, inconsistent, or weakly supported.

                        ========================
                        NON-NEGOTIABLE RULES
                        ========================
                        - Ground every judgment in the provided evidence pack and input context only.
                        - Do NOT invent facts.
                        - Do NOT normalize, enrich, or repair content silently.
                        - Do NOT assume missing values.
                        - Do NOT accept domain-plausible claims unless they are evidenced.
                        - If evidence is weak, ambiguous, indirect, or absent, you must lower the relevant score(s).
                        - If a candidate field cannot be traced back to evidence, treat it as unsupported.
                        - If multiple evidence items disagree, record an explicit conflict.
                        - If the candidate uses stronger wording than the evidence supports, treat it as overclaiming.
                        - When in doubt, be conservative.

                        ========================
                        EVALUATION PHILOSOPHY
                        ========================
                        This is a validation-and-adjudication step, not a creative generation step.

                        Prefer:
                        - “insufficient evidence”
                        - “partially supported”
                        - “conflicting evidence”
                        - “needs repair”

                        Over:
                        - speculative completion
                        - generous interpretation
                        - best-guess filling

                        ========================
                        FIELD-LEVEL VALIDATION EXPECTATIONS
                        ========================
                        For each meaningful field in the candidate, implicitly evaluate:
                        - Is the field present in the expected schema?
                        - Is the value type appropriate?
                        - Is the value explicitly supported by one or more evidence items?
                        - Is the wording faithful to the evidence?
                        - Is the confidence proportional to evidence strength?
                        - Does it contradict any sibling field, graph relation, or evidence item?
                        - Is it overly broad, overly specific, or improperly normalized?

                        ========================
                        SCORING DIMENSIONS
                        ========================
                        Return all of the following scores in [0,1]:

                        1. schema_validity_score
                        Meaning:
                        - Are required structures present?
                        - Are field names/types/containers correct?
                        - Is the output shape valid and machine-usable?

                        2. evidence_alignment_score
                        Meaning:
                        - Are candidate claims directly supported by evidence?
                        - Are evidence links sufficient, specific, and relevant?
                        - Are there unsupported or weakly supported claims?

                        3. graph_consistency_score
                        Meaning:
                        - Is the candidate consistent with the provided graph/context snapshot?
                        - Are there relation-level contradictions or entity mismatches?

                        4. completeness_score
                        Meaning:
                        - Has the candidate captured the major evidence-supported facts that should reasonably be extracted?
                        - Are important evidence-backed fields omitted?

                        5. conservativeness_score
                        Meaning:
                        - Does the candidate avoid hallucination and overclaiming?
                        - Does it remain appropriately cautious under uncertainty?

                        Also return:
                        - total_score in [0,1]

                        ========================
                        TOTAL SCORE GUIDANCE
                        ========================
                        The total_score must reflect a balanced judgment, not a naive average if severe defects exist.

                        Use these principles:
                            - Severe unsupported claims should strongly depress total_score.
                            - Major schema breakage should strongly depress total_score.
                            - Hard contradictions should strongly depress total_score.
                            - Missing minor optional fields should not be treated as fatal.
                            - Conservative but slightly incomplete outputs are preferable to imaginative outputs.

                        Suggested internal weighting mindset:
                            - evidence alignment: highest importance
                            - conservativeness: very high importance
                            - schema validity: high importance
                            - graph consistency: medium-high importance
                            - completeness: medium importance

                        If needed, you may effectively penalize total_score more than the arithmetic mean when critical violations are present.

                        ========================
                        CONFLICT DETECTION
                        ========================
                        When conflicts exist, add entries to conflict_set.

                        Each conflict entry must contain:
                        - field_path: JSON-style path or dotted path of the problematic field
                        - conflict_type: one of
                        ["missing_evidence", "contradictory_evidence", "schema_error", "entity_mismatch", "overclaim", "type_error", "graph_inconsistency", "ambiguous_mapping", "missing_required_field"]
                        - candidate_values: the candidate value(s) causing the issue
                        - related_evidence_ids: list of evidence ids relevant to the conflict
                        - severity: one of ["low", "medium", "high", "critical"]
                        - explanation: concise, evidence-grounded explanation

                        ========================
                        REPAIR INSTRUCTIONS
                        ========================
                        If the candidate is not production-ready, set needs_repair = true.

                        repair_instruction must be actionable and structured.
                        It should tell the upstream extractor/worker what to do next, such as:
                        - remove unsupported field
                        - weaken claim wording
                        - split merged entities
                        - add evidence link
                        - mark value as unknown
                        - re-extract from specific evidence items
                        - preserve only consensus facts
                        - fill missing required container
                        - resolve contradictory evidence explicitly

                        Do not output vague advice like “improve quality”.
                        Make repair instructions directly operational.

                        ========================
                        OUTPUT STYLE
                        ========================
                        - Output JSON only.
                        - No markdown.
                        - No prose outside JSON.
                        - No code fences.
                        - Keep explanations concise but precise.
                        - Every major issue should be traceable to evidence or schema/context constraints.

                        ========================
                        DECISION STANDARD
                        ========================
                        A candidate is acceptable only if it is:
                        - structurally valid,
                        - evidence-grounded,
                        - internally consistent,
                        - sufficiently complete for the task,
                        - and conservative under uncertainty.

                        If these conditions are not met, it must be marked as needing repair.
                    """
                ),
            ),
            "repair_conflicts": PromptTemplate(
                name="repair_conflicts",
                version="v1",
                template=(
                    "You are Repair worker.\n"
                    "Only patch conflict fields from conflict_set.\n"
                    "Never rerun full extraction.\n"
                    "Return JSON of updated fields and evidence mapping."
                ),
            ),
            "exposure_assessment": PromptTemplate(
                name="exposure_assessment",
                version="v1",
                template=(
                    "You are a conservative telecom exposure assessor for 3GPP/IMS/VoWiFi/Open Gateway.\n"
                    "Input is candidate host, graph-derived evidence, and probe observations.\n"
                    "You must output STRICT JSON with keys:\n"
                    "risk_level(low|medium|high|critical), score(0..1), summary, conservative_explanation,\n"
                    "attack_surface_notes(list), missing_evidence(list), evidence_refs(list).\n"
                    "Do not invent facts. Use evidence-first and conservative language. "
                    "Never provide exploitation steps."
                ),
            ),
            "graph_merge_normalization": PromptTemplate(
                name="graph_merge_normalization",
                version="v1",
                template=(
                    "Normalize staging nodes into existing ontology naming."
                    " Prefer existing IDs when equivalent."
                ),
            ),
            "report_generation": PromptTemplate(
                name="report_generation",
                version="v1",
                template=(
                    "Generate markdown report for extraction run: input, evidence, worker/judge,"
                    " repair, staging, human merge."
                ),
            ),
        }
        self._load_overrides()

    def get(self, name: str) -> PromptTemplate:
        if name not in self._prompts:
            raise KeyError(f"prompt not found: {name}")
        return self._prompts[name]

    def list_versions(self) -> list[dict[str, str]]:
        return [
            {
                "name": p.name,
                "version": p.version,
                "hash": self.compute_hash(p.template),
                "source": p.source,
            }
            for p in self._prompts.values()
        ]

    def get_metadata(self, name: str) -> dict[str, str]:
        p = self.get(name)
        return {"name": p.name, "version": p.version, "hash": self.compute_hash(p.template)}

    def compute_hash(self, template: str) -> str:
        return hashlib.sha256(template.encode("utf-8")).hexdigest()

    def _load_overrides(self) -> None:
        override_path = Path(settings.extraction_prompt_override_path)
        if not override_path.exists():
            return
        try:
            raw = json.loads(override_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return
        if not isinstance(raw, dict):
            return
        prompt_items = raw.get("prompts", {})
        if not isinstance(prompt_items, dict):
            return
        for name, payload in prompt_items.items():
            if not isinstance(payload, dict):
                continue
            template = payload.get("template")
            if not isinstance(template, str) or not template.strip():
                continue
            version = str(payload.get("version") or "v_override")
            self._prompts[name] = PromptTemplate(
                name=name,
                version=version,
                template=template,
                source=str(override_path),
            )


prompt_registry = PromptRegistryService()

