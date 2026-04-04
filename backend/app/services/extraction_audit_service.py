from __future__ import annotations

from app.schemas.extraction_pipeline import ExtractionResult


class ExtractionAuditService:
    """Deterministic post-extraction validator/auditor."""

    def audit(self, result: ExtractionResult) -> dict:
        issues: list[dict[str, str]] = []
        state_ids = {s.temp_id for s in result.states}
        state_names = set()
        for st in result.states:
            if not st.evidence_ids:
                issues.append(
                    {"code": "MISSING_EVIDENCE", "detail": f"state {st.temp_id} has no evidence_ids"}
                )
            if st.normalized_name in state_names:
                issues.append(
                    {
                        "code": "NAMING_CONFLICT",
                        "detail": f"duplicate normalized state name: {st.normalized_name}",
                    }
                )
            state_names.add(st.normalized_name)
        for tr in result.transitions:
            if tr.from_state not in state_ids or tr.to_state not in state_ids:
                issues.append(
                    {
                        "code": "BROKEN_TRANSITION",
                        "detail": f"{tr.temp_id} references missing from/to state",
                    }
                )
            if not tr.evidence_ids:
                issues.append(
                    {"code": "MISSING_EVIDENCE", "detail": f"transition {tr.temp_id} has no evidence_ids"}
                )
        return {"ok": len(issues) == 0, "issues": issues}


extraction_audit_service = ExtractionAuditService()

