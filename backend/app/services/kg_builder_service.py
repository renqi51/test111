from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.repositories.graph_repository import get_graph_repository
from app.schemas.kg_extraction import (
    ExtractedEdge,
    ExtractedEvidence,
    ExtractedNode,
    ExtractionResult,
    LocalImportResponse,
)
from app.utils.file_parser import chunk_text, iter_input_documents, read_rule_context

logger = logging.getLogger(__name__)


class KGBuilderService:
    async def process_document_chunk(
        self,
        chunk_text_value: str,
        source_file: str,
        chunk_index: int,
        rule_context: str,
    ) -> ExtractionResult:
        schema_json = json.dumps(ExtractionResult.model_json_schema(), ensure_ascii=False)
        system_prompt = (
            "你是电信标准知识图谱抽取助手。"
            "只抽取有证据支持的信息，不要臆造，不要补全未出现事实。"
            "返回 JSON，必须满足给定 Schema。"
        )
        user_prompt = (
            f"规则:\n{rule_context or '(no-rules)'}\n\n"
            f"source_file={source_file}, chunk_index={chunk_index}\n"
            f"schema={schema_json}\n\n"
            "输出要求:\n"
            "1) 仅返回 nodes / edges\n"
            "2) 每个 node/edge 尽量包含 evidence[source_file, chunk_index, quote]\n"
            "3) 无证据支持的实体关系不要输出\n\n"
            f"文本:\n{chunk_text_value}"
        )
        try:
            llm_res = await get_llm_provider().chat_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model_name=settings.extraction_worker_model,
                temperature=0.1,
            )
            extracted = ExtractionResult.model_validate(llm_res.raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("kg chunk parse failed file=%s chunk=%s err=%s", source_file, chunk_index, str(exc)[:220])
            return ExtractionResult(nodes=[], edges=[])

        fallback = ExtractedEvidence(source_file=source_file, chunk_index=chunk_index, quote=chunk_text_value[:240].strip())
        for node in extracted.nodes:
            if not node.evidence:
                node.evidence = [fallback]
        for edge in extracted.edges:
            if not edge.evidence:
                edge.evidence = [fallback]
        return extracted

    async def build_graph_from_input(self, *, dry_run: bool = False, max_files: int | None = None) -> dict[str, Any]:
        notes: list[str] = []
        if not (settings.llm_provider and settings.llm_base_url):
            notes.append("LLM is not configured; skip local import.")
            return LocalImportResponse(
                files_processed=0,
                files_failed=0,
                chunks_processed=0,
                nodes_extracted_raw=0,
                edges_extracted_raw=0,
                nodes_merged=0,
                edges_merged=0,
                dry_run=dry_run,
                failed_files=[],
                notes=notes,
            ).model_dump()

        input_dir = Path(settings.kg_input_dir)
        rule_dir = Path(settings.kg_rule_dir)
        rule_context = read_rule_context(rule_dir)

        failed_files: list[str] = []
        docs = self._collect_input_docs(input_dir, failed_files)
        if max_files is not None and max_files > 0:
            docs = docs[:max_files]

        raw_nodes: list[ExtractedNode] = []
        raw_edges: list[ExtractedEdge] = []
        files_processed = 0
        chunks_processed = 0

        for source_file, full_text in docs:
            chunks = chunk_text(
                full_text,
                chunk_size=settings.kg_chunk_size,
                chunk_overlap=settings.kg_chunk_overlap,
            )
            if not chunks:
                failed_files.append(f"{source_file}: empty_after_chunking")
                continue
            files_processed += 1
            for ch in chunks:
                chunks_processed += 1
                result = await self.process_document_chunk(
                    chunk_text_value=str(ch["text"]),
                    source_file=source_file,
                    chunk_index=int(ch["chunk_index"]),
                    rule_context=rule_context,
                )
                raw_nodes.extend(result.nodes)
                raw_edges.extend(result.edges)

        merged_nodes, merged_edges = self._normalize_and_merge(raw_nodes, raw_edges)
        nodes_payload = [self._node_to_graph_payload(n) for n in merged_nodes.values()]
        edges_payload = [self._edge_to_graph_payload(e) for e in merged_edges.values()]

        if not dry_run:
            repo = get_graph_repository()
            repo.merge_nodes_edges(nodes_payload, edges_payload)

        return LocalImportResponse(
            files_processed=files_processed,
            files_failed=len(failed_files),
            chunks_processed=chunks_processed,
            nodes_extracted_raw=len(raw_nodes),
            edges_extracted_raw=len(raw_edges),
            nodes_merged=len(nodes_payload),
            edges_merged=len(edges_payload),
            dry_run=dry_run,
            failed_files=failed_files,
            notes=notes,
        ).model_dump()

    def normalize_node_id(self, value: str) -> str:
        v = (value or "").strip().lower()
        v = re.sub(r"\s+", "_", v)
        v = re.sub(r"[^a-z0-9._:-]+", "_", v)
        v = re.sub(r"_+", "_", v).strip("_")
        return v[:160]

    def normalize_relation(self, value: str) -> str:
        v = (value or "").strip().lower()
        v = v.replace("-", "_").replace(" ", "_")
        v = re.sub(r"[^a-z0-9_]+", "_", v)
        v = re.sub(r"_+", "_", v).strip("_")
        return v[:120]

    def normalize_node(self, node: ExtractedNode) -> ExtractedNode | None:
        node_id = self.normalize_node_id(node.id or node.label)
        if not node_id:
            return None
        label = (node.label or node_id).strip()
        ntype = (node.type or "Unknown").strip()
        properties = dict(node.properties or {})
        evidences = self._normalize_evidence_list(node.evidence)
        return ExtractedNode(id=node_id, label=label, type=ntype, properties=properties, evidence=evidences)

    def normalize_edge(self, edge: ExtractedEdge) -> ExtractedEdge | None:
        source = self.normalize_node_id(edge.source)
        target = self.normalize_node_id(edge.target)
        interaction = self.normalize_relation(edge.interaction)
        if not source or not target or not interaction:
            return None
        properties = dict(edge.properties or {})
        evidences = self._normalize_evidence_list(edge.evidence)
        return ExtractedEdge(
            source=source,
            target=target,
            interaction=interaction,
            properties=properties,
            evidence=evidences,
        )

    def _collect_input_docs(self, input_dir: Path, failed_files: list[str]) -> list[tuple[str, str]]:
        docs: list[tuple[str, str]] = []
        if not input_dir.exists():
            failed_files.append(f"{str(input_dir)}: input_dir_not_found")
            return docs

        supported = {".md", ".pdf"}
        all_files = sorted([p for p in input_dir.iterdir() if p.is_file() and p.suffix.lower() in supported])
        valid_names: set[str] = set()
        for source_file, full_text in iter_input_documents(input_dir):
            valid_names.add(source_file)
            if not full_text.strip():
                failed_files.append(f"{source_file}: empty_file")
                continue
            docs.append((source_file, full_text))

        for p in all_files:
            if p.name not in valid_names:
                failed_files.append(f"{p.name}: read_failed_or_unsupported")
        return docs

    def _normalize_evidence_list(self, evidences: list[ExtractedEvidence]) -> list[ExtractedEvidence]:
        out: list[ExtractedEvidence] = []
        seen: set[tuple[str, int, str]] = set()
        for ev in evidences:
            source_file = (ev.source_file or "").strip()
            chunk_index = int(ev.chunk_index)
            quote = (ev.quote or "").strip()
            key = (source_file, chunk_index, quote)
            if key in seen:
                continue
            seen.add(key)
            out.append(ExtractedEvidence(source_file=source_file, chunk_index=chunk_index, quote=quote))
        return out

    def _normalize_and_merge(
        self,
        nodes: list[ExtractedNode],
        edges: list[ExtractedEdge],
    ) -> tuple[dict[str, ExtractedNode], dict[tuple[str, str, str], ExtractedEdge]]:
        merged_nodes: dict[str, ExtractedNode] = {}
        for node in nodes:
            normalized = self.normalize_node(node)
            if normalized is None:
                continue
            if normalized.id not in merged_nodes:
                merged_nodes[normalized.id] = normalized
                continue
            old = merged_nodes[normalized.id]
            old.properties = self._merge_dict(old.properties, normalized.properties)
            old.evidence = self._merge_evidence(old.evidence, normalized.evidence)
            if not old.label and normalized.label:
                old.label = normalized.label
            if old.type == "Unknown" and normalized.type:
                old.type = normalized.type

        merged_edges: dict[tuple[str, str, str], ExtractedEdge] = {}
        for edge in edges:
            normalized = self.normalize_edge(edge)
            if normalized is None:
                continue
            if normalized.source not in merged_nodes or normalized.target not in merged_nodes:
                continue
            key = (normalized.source, normalized.target, normalized.interaction)
            if key not in merged_edges:
                merged_edges[key] = normalized
                continue
            old = merged_edges[key]
            old.properties = self._merge_dict(old.properties, normalized.properties)
            old.evidence = self._merge_evidence(old.evidence, normalized.evidence)
        return merged_nodes, merged_edges

    def _merge_dict(self, old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
        out = dict(old or {})
        for k, v in (new or {}).items():
            if k not in out:
                out[k] = v
                continue
            if isinstance(out[k], dict) and isinstance(v, dict):
                out[k] = self._merge_dict(out[k], v)
                continue
            out[k] = v
        return out

    def _merge_evidence(self, old: list[ExtractedEvidence], new: list[ExtractedEvidence]) -> list[ExtractedEvidence]:
        return self._normalize_evidence_list((old or []) + (new or []))

    def _node_to_graph_payload(self, node: ExtractedNode) -> dict[str, Any]:
        description = str(node.properties.get("description", "")).strip()
        if not description:
            description = (node.properties.get("summary") or node.label or "")[:220]
        evidence_source = self._compress_evidence_source(node.evidence)
        return {
            "id": node.id,
            "label": node.label,
            "type": node.type,
            "description": description,
            "evidence_source": evidence_source,
            "en_identifier": node.properties.get("en_identifier") or node.id,
        }

    def _edge_to_graph_payload(self, edge: ExtractedEdge) -> dict[str, Any]:
        return {
            "source": edge.source,
            "target": edge.target,
            "interaction": edge.interaction,
        }

    def _compress_evidence_source(self, evidence: list[ExtractedEvidence]) -> str:
        chunks: list[str] = []
        for ev in evidence[:3]:
            quote = (ev.quote or "").replace("\n", " ").strip()
            quote = quote[:80]
            chunks.append(f"{ev.source_file}#chunk-{ev.chunk_index}: {quote}")
        return " | ".join(chunks)


_kg_builder_service: KGBuilderService | None = None


def get_kg_builder_service() -> KGBuilderService:
    global _kg_builder_service
    if _kg_builder_service is None:
        _kg_builder_service = KGBuilderService()
    return _kg_builder_service

