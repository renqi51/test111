from __future__ import annotations

import re

from app.schemas.extraction_pipeline import (
    ExtractionResult,
    JudgeDecision,
    StagingGraph,
    StagingGraphEdge,
    StagingGraphNode,
)


class StagingGraphService:
    def build(
        self,
        run_id: str,
        document_id: str,
        extraction: ExtractionResult,
        judge: JudgeDecision,
    ) -> StagingGraph:
        score_map = {d.worker_name: d.total_score for d in judge.score_details}
        worker_score = score_map.get(extraction.worker_name, 0.0)
        nodes: list[StagingGraphNode] = []
        state_id_map: dict[str, str] = {}
        for st in extraction.states:
            node_id = self._canonical_state_id(st.temp_id, st.normalized_name, st.name)
            state_id_map[st.temp_id] = node_id
            nodes.append(
                StagingGraphNode(
                    id=node_id,
                    label=st.name,
                    type=st.state_type,
                    properties={
                        "normalized_name": st.normalized_name,
                        "description": st.description,
                        "confidence": st.confidence,
                        "attributes": st.attributes,
                    },
                    source_doc_id=document_id,
                    source_chunk_ids=st.evidence_ids,
                    source_worker=extraction.worker_name,
                    judge_score=worker_score,
                )
            )
        edges: list[StagingGraphEdge] = []
        for tr in extraction.transitions:
            source_id = state_id_map.get(tr.from_state, tr.from_state)
            target_id = state_id_map.get(tr.to_state, tr.to_state)
            edges.append(
                StagingGraphEdge(
                    source=source_id,
                    target=target_id,
                    interaction=tr.trigger or "state_transition",
                    properties={
                        "guard": tr.guard,
                        "action": tr.action,
                        "confidence": tr.confidence,
                        "attributes": tr.attributes,
                    },
                    source_doc_id=document_id,
                    source_chunk_ids=tr.evidence_ids,
                    source_worker=extraction.worker_name,
                    judge_score=worker_score,
                )
            )
        return StagingGraph(
            run_id=run_id,
            document_id=document_id,
            nodes=nodes,
            edges=edges,
            metadata={"recommended_worker": judge.recommended_worker},
        )

    def _canonical_state_id(self, temp_id: str, normalized_name: str, name: str) -> str:
        # Prefer human-readable normalized ids instead of state_1/state_2 placeholders.
        if temp_id.startswith("state_") or re.fullmatch(r"st_\d+", temp_id):
            base = (normalized_name or name or temp_id).strip().lower().replace(" ", "_")
            base = re.sub(r"[^a-z0-9_]+", "_", base).strip("_") or temp_id
            return f"state_{base}"
        return temp_id


staging_graph_service = StagingGraphService()

