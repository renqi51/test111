from __future__ import annotations

from copy import deepcopy

from app.schemas.extraction_pipeline import (
    ConflictItem,
    ExtractionResult,
    JudgeDecision,
    RepairedExtractionResult,
)
from app.services.prompt_registry_service import prompt_registry


class RepairService:
    def repair(
        self,
        run_id: str,
        preferred_result: ExtractionResult,
        conflicts: list[ConflictItem],
        judge: JudgeDecision,
    ) -> RepairedExtractionResult:
        _ = prompt_registry.get("repair_conflicts")
        fixed = deepcopy(preferred_result)
        updated: list[str] = []
        unresolved: list[ConflictItem] = []

        for c in conflicts:
            if c.field_path == "states.names":
                # Local repair policy: keep preferred states but dedup normalized names.
                seen: set[str] = set()
                deduped = []
                for st in fixed.states:
                    if st.normalized_name in seen:
                        continue
                    seen.add(st.normalized_name)
                    deduped.append(st)
                fixed.states = deduped
                updated.append(c.field_path)
            elif c.field_path in ("states.length", "transitions.length"):
                updated.append(c.field_path)
            else:
                unresolved.append(c)

        fixed.extraction_mode = "repair"
        fixed.assumptions.append("Field-level repair applied from judge conflict_set.")
        return RepairedExtractionResult(
            run_id=run_id,
            updated_fields=updated,
            extraction_result=fixed,
            unresolved_conflicts=unresolved,
            notes=[judge.repair_instruction] if judge.repair_instruction else [],
        )


repair_service = RepairService()

