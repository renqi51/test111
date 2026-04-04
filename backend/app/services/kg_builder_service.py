from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.repositories.graph_repository import get_graph_repository
from app.schemas.kg_extraction import ExtractedEdge, ExtractedNode, ExtractionResult
from app.utils.file_parser import chunk_text, load_input_documents, load_rule_context

logger = logging.getLogger(__name__)

ALLOWED_NODE_TYPES = {
    "service": "Service",
    "networkfunction": "NetworkFunction",
    "protocol": "Protocol",
    "fqdnpattern": "FQDNPattern",
    "standarddoc": "StandardDoc",
    "riskhypothesis": "RiskHypothesis",
    "workproduct": "WorkProduct",
    "capability": "Capability",
    "interface": "Interface",
    "platform": "Platform",
    "namingrule": "NamingRule",
    "unknown": "Unknown",
}


class KGBuilderService:
    async def process_document_chunk(
        self,
        chunk_text_value: str,
        source_file: str,
        chunk_index: int,
        rule_context: str,
    ) -> ExtractionResult:
        schema_json = json.dumps(ExtractionResult.model_json_schema(), ensure_ascii=False, indent=2)
        system_prompt = (
            "你是 3GPP/GSMA 领域知识图谱抽取助手。"
            "你必须基于输入文本和规则抽取节点与边，不能臆造。"
            "仅输出严格合法 JSON。"
        )
        user_prompt = (
            f"规则上下文:\n{rule_context or '(no rules)'}\n\n"
            f"输入来源: source_file={source_file}, chunk_index={chunk_index}\n\n"
            "请抽取 nodes 和 edges。\n"
            "- 节点必须包含: id, label, type\n"
            "- 边必须包含: source, target, interaction\n"
            "- 每条 node/edge 尽量附带 evidence，且 evidence 至少包含 source_file, chunk_index, quote\n"
            "- 仅提取有文本证据支持的内容\n"
            "- 关系 interaction 优先使用 lower_snake_case\n\n"
            f"JSON Schema:\n{schema_json}\n\n"
            f"文本内容:\n{chunk_text_value}\n"
        )
        try:
            llm = await get_llm_provider().chat_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model_name=settings.extraction_worker_model,
                temperature=0.1,
            )
            parsed = ExtractionResult.model_validate(llm.raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("chunk extraction failed: %s:%s err=%s", source_file, chunk_index, str(exc)[:220])
            return ExtractionResult(nodes=[], edges=[])
        return self._fill_missing_evidence(parsed, source_file=source_file, chunk_index=chunk_index, chunk_text_value=chunk_text_value)

    async def build_graph_from_input(
        self,
        *,
        dry_run: bool = False,
        max_files: int | None = None,
    ) -> dict[str, Any]:
        input_dir = Path(settings.kg_input_dir)
        rule_dir = Path(settings.kg_rule_dir)
        rule_context = load_rule_context(rule_dir)
        documents, failed_files = load_input_documents(input_dir)
        if max_files is not None and max_files > 0:
            documents = documents[:max_files]

        all_nodes_raw: list[ExtractedNode] = []
        all_edges_raw: list[ExtractedEdge] = []
        chunks_processed = 0
        files_processed = 0

        for doc in documents:
            chunks = chunk_text(
                doc.text,
                doc.source_file,
                chunk_size=settings.kg_chunk_size,
                chunk_overlap=settings.kg_chunk_overlap,
            )
            if not chunks:
                continue
            files_processed += 1
            for chunk in chunks:
                chunks_processed += 1
                result = await self.process_document_chunk(
                    chunk_text_value=str(chunk["text"]),
                    source_file=str(chunk["source_file"]),
                    chunk_index=int(chunk["chunk_index"]),
                    rule_context=rule_context,
                )
                all_nodes_raw.extend(result.nodes)
                all_edges_raw.extend(result.edges)

        normalized_nodes, normalized_edges = self._normalize_and_deduplicate(all_nodes_raw, all_edges_raw)
        stats = {
            "files_processed": files_processed,
            "files_failed": len(failed_files),
            "failed_files": failed_files,
            "chunks_processed": chunks_processed,
            "nodes_extracted_raw": len(all_nodes_raw),
            "edges_extracted_raw": len(all_edges_raw),
            "nodes_merged": len(normalized_nodes),
            "edges_merged": len(normalized_edges),
            "dry_run": dry_run,
        }
        if dry_run:
            return stats

        repo = get_graph_repository()
        repo.merge_nodes(normalized_nodes)
        repo.merge_edges(normalized_edges)
        return stats

    def _normalize_and_deduplicate(
        self,
        nodes: list[ExtractedNode],
        edges: list[ExtractedEdge],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        dedup_nodes: dict[tuple[str, str], dict[str, Any]] = {}
        for node in nodes:
            normalized_id = self._normalize_identifier(node.id or node.label)
            normalized_label = (node.label or normalized_id).strip()
            normalized_type = self._normalize_node_type(node.type)
            key = (normalized_type, normalized_id)
            payload = {
                "id": normalized_id,
                "label": normalized_label,
                "type": normalized_type,
                "description": str(node.properties.get("description", "")).strip(),
                "evidence_source": "kg_builder_local_import",
                "en_identifier": normalized_id,
                "properties": dict(node.properties or {}),
                "evidence": self._normalize_evidence(node.evidence, "", -1, ""),
            }
            if key not in dedup_nodes:
                dedup_nodes[key] = payload
                continue
            existing = dedup_nodes[key]
            existing["properties"] = self._merge_dict(existing.get("properties"), payload.get("properties"))
            existing["evidence"] = self._merge_evidence(existing.get("evidence"), payload.get("evidence"))
            if not existing.get("description") and payload.get("description"):
                existing["description"] = payload["description"]

        node_id_index = {v["id"] for v in dedup_nodes.values()}
        dedup_edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        for edge in edges:
            source = self._normalize_identifier(edge.source)
            target = self._normalize_identifier(edge.target)
            interaction = self._normalize_interaction(edge.interaction)
            if not source or not target or not interaction:
                continue
            if source not in node_id_index or target not in node_id_index:
                continue
            key = (source, target, interaction)
            payload = {
                "source": source,
                "target": target,
                "interaction": interaction,
                "properties": dict(edge.properties or {}),
                "evidence": self._normalize_evidence(edge.evidence, "", -1, ""),
            }
            if key not in dedup_edges:
                dedup_edges[key] = payload
                continue
            existing = dedup_edges[key]
            existing["properties"] = self._merge_dict(existing.get("properties"), payload.get("properties"))
            existing["evidence"] = self._merge_evidence(existing.get("evidence"), payload.get("evidence"))
        return list(dedup_nodes.values()), list(dedup_edges.values())

    def _fill_missing_evidence(
        self,
        result: ExtractionResult,
        *,
        source_file: str,
        chunk_index: int,
        chunk_text_value: str,
    ) -> ExtractionResult:
        quote = chunk_text_value[:240]
        for node in result.nodes:
            node.evidence = self._normalize_evidence(node.evidence, source_file, chunk_index, quote)
        for edge in result.edges:
            edge.evidence = self._normalize_evidence(edge.evidence, source_file, chunk_index, quote)
        return result

    def _normalize_evidence(
        self,
        evidence: list[dict[str, Any]] | None,
        source_file: str,
        chunk_index: int,
        fallback_quote: str,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in evidence or []:
            if not isinstance(item, dict):
                continue
            sf = str(item.get("source_file") or source_file).strip()
            ci = item.get("chunk_index", chunk_index)
            try:
                ci_int = int(ci)
            except Exception:  # noqa: BLE001
                ci_int = chunk_index
            quote = str(item.get("quote") or item.get("evidence_text") or fallback_quote).strip()
            if not sf:
                sf = source_file
            out.append({"source_file": sf, "chunk_index": ci_int, "quote": quote})
        if not out:
            out.append({"source_file": source_file, "chunk_index": chunk_index, "quote": fallback_quote.strip()})
        return out

    def _normalize_identifier(self, value: str) -> str:
        clean = (value or "").strip().lower()
        clean = re.sub(r"\s+", "_", clean)
        clean = re.sub(r"[^a-z0-9._:-]+", "_", clean)
        clean = re.sub(r"_+", "_", clean).strip("_")
        return clean[:160]

    def _normalize_node_type(self, value: str) -> str:
        key = re.sub(r"[^a-zA-Z0-9]+", "", (value or "").strip().lower())
        return ALLOWED_NODE_TYPES.get(key, "Unknown")

    def _normalize_interaction(self, value: str) -> str:
        clean = (value or "").strip().lower()
        clean = clean.replace("-", "_").replace(" ", "_")
        clean = re.sub(r"[^a-z0-9_]+", "_", clean)
        clean = re.sub(r"_+", "_", clean).strip("_")
        return clean[:120]

    def _merge_dict(self, left: dict[str, Any] | None, right: dict[str, Any] | None) -> dict[str, Any]:
        out = dict(left or {})
        for k, v in (right or {}).items():
            if k not in out:
                out[k] = v
                continue
            if isinstance(out[k], dict) and isinstance(v, dict):
                out[k] = self._merge_dict(out[k], v)
                continue
            out[k] = v
        return out

    def _merge_evidence(
        self,
        left: list[dict[str, Any]] | None,
        right: list[dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str]] = set()
        for item in (left or []) + (right or []):
            if not isinstance(item, dict):
                continue
            sf = str(item.get("source_file", "")).strip()
            ci_raw = item.get("chunk_index", -1)
            try:
                ci = int(ci_raw)
            except Exception:  # noqa: BLE001
                ci = -1
            quote = str(item.get("quote", "")).strip()
            key = (sf, ci, quote)
            if key in seen:
                continue
            seen.add(key)
            merged.append({"source_file": sf, "chunk_index": ci, "quote": quote})
        return merged


_kg_builder_service: KGBuilderService | None = None


def get_kg_builder_service() -> KGBuilderService:
    global _kg_builder_service
    if _kg_builder_service is None:
        _kg_builder_service = KGBuilderService()
    return _kg_builder_service
