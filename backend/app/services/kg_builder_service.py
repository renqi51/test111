from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
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
from app.utils.file_parser import chunk_text, iter_input_documents, read_rule_context_multi, supported_input_suffixes

logger = logging.getLogger(__name__)


class KGBuilderService:
    @staticmethod
    def _now_str() -> str:
        """返回本地时区时间字符串，便于终端直接观察进度时间点。"""
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    def _append_dlq_record(
        self,
        *,
        source_file: str,
        chunk_index: int,
        error: str,
        chunk_text_value: str,
    ) -> None:
        """
        记录 chunk 级别失败到本地 jsonl（死信队列）：
        - 不影响主流程继续处理后续 chunk；
        - 便于离线重放与问题定位。
        """
        path = Path(settings.kg_builder_dlq_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_file": source_file,
            "chunk_index": chunk_index,
            "error": error[:500],
            "chunk_preview": chunk_text_value[:500],
        }
        with path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")

    async def _process_chunks_concurrently(
        self,
        *,
        source_file: str,
        chunks: list[dict[str, Any]],
        rule_context: str,
    ) -> tuple[list[ExtractedNode], list[ExtractedEdge], int, int]:
        """
        并发处理单文件 chunk：
        - 使用本地并发阈值限制 task fan-out；
        - 实际上游并发上限由 llm_provider 的全局 Semaphore 兜底；
        - 任一 chunk 失败会写 DLQ，但不会中断整体文件处理。
        """
        chunk_concurrency = max(1, int(settings.kg_builder_chunk_concurrency))
        sem = asyncio.Semaphore(chunk_concurrency)
        window_size = max(4, chunk_concurrency * 4)

        async def _run_one(chunk_payload: dict[str, Any]) -> tuple[int, ExtractionResult]:
            chunk_index = int(chunk_payload["chunk_index"])
            chunk_text_value = str(chunk_payload["text"])
            async with sem:
                try:
                    result = await self.process_document_chunk(
                        chunk_text_value=chunk_text_value,
                        source_file=source_file,
                        chunk_index=chunk_index,
                        rule_context=rule_context,
                    )
                    return chunk_index, result
                except Exception as exc:  # noqa: BLE001
                    err = str(exc)[:220]
                    logger.exception("kg chunk fatal failed file=%s chunk=%s err=%s", source_file, chunk_index, err)
                    try:
                        self._append_dlq_record(
                            source_file=source_file,
                            chunk_index=chunk_index,
                            error=err,
                            chunk_text_value=chunk_text_value,
                        )
                    except Exception:  # noqa: BLE001
                        logger.exception("failed to write DLQ record file=%s chunk=%s", source_file, chunk_index)
                    return chunk_index, ExtractionResult(nodes=[], edges=[])

        raw_nodes: list[ExtractedNode] = []
        raw_edges: list[ExtractedEdge] = []
        pending: list[asyncio.Task[tuple[int, ExtractionResult]]] = []
        total_chunks = len(chunks)
        completed_chunks = 0
        ok_chunks = 0
        empty_or_failed_chunks = 0
        progress_log_step = max(20, total_chunks // 20 or 1)

        logger.info("[%s] [KG] file=%s start total_chunks=%s", self._now_str(), source_file, total_chunks)

        def _consume_done(done_items: list[tuple[int, ExtractionResult]]) -> None:
            nonlocal completed_chunks, ok_chunks, empty_or_failed_chunks
            done_items.sort(key=lambda item: item[0])
            for chunk_index, result in done_items:
                raw_nodes.extend(result.nodes)
                raw_edges.extend(result.edges)
                completed_chunks += 1
                if result.nodes or result.edges:
                    ok_chunks += 1
                    status = "ok"
                else:
                    empty_or_failed_chunks += 1
                    status = "empty_or_failed"
                if (
                    completed_chunks % progress_log_step == 0
                    or completed_chunks == total_chunks
                ):
                    logger.info(
                        "[%s] [KG] file=%s progress=%s/%s chunk=%s status=%s ok=%s empty_or_failed=%s",
                        self._now_str(),
                        source_file,
                        completed_chunks,
                        total_chunks,
                        chunk_index,
                        status,
                        ok_chunks,
                        empty_or_failed_chunks,
                    )

        for chunk_payload in chunks:
            pending.append(asyncio.create_task(_run_one(chunk_payload)))
            if len(pending) >= window_size:
                done = await asyncio.gather(*pending)
                _consume_done(done)
                pending.clear()

        if pending:
            done = await asyncio.gather(*pending)
            _consume_done(done)

        logger.info(
            "[%s] [KG] file=%s done total_chunks=%s ok=%s empty_or_failed=%s nodes=%s edges=%s",
            self._now_str(),
            source_file,
            total_chunks,
            ok_chunks,
            empty_or_failed_chunks,
            len(raw_nodes),
            len(raw_edges),
        )

        return raw_nodes, raw_edges, ok_chunks, empty_or_failed_chunks

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
            "当文本出现可利用面、缺陷、错误配置、威胁手法时，必须优先抽取为 "
            "type=Vulnerability（CVE/错误配置/标准缺陷）或 type=ThreatVector（攻击载荷/手法），"
            "并通过 vulnerable_to / enables_vector 等与 Protocol、NetworkFunction、Interface 建立有证据的边。"
            "返回 JSON，必须满足给定 Schema。"
        )
        user_prompt = (
            f"规则:\n{rule_context or '(no-rules)'}\n\n"
            f"source_file={source_file}, chunk_index={chunk_index}\n"
            f"schema={schema_json}\n\n"
            "输出要求:\n"
            "1) 仅返回 nodes / edges\n"
            "2) 每个 node/edge 尽量包含 evidence[source_file, chunk_index, quote]\n"
            "3) 无证据支持的实体关系不要输出\n"
            "4) 若存在协议层面的弱点或攻击路径描述，应落地为 Vulnerability/ThreatVector 节点及 vulnerable_to、enables_vector 关系\n\n"
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
            try:
                self._append_dlq_record(
                    source_file=source_file,
                    chunk_index=chunk_index,
                    error=str(exc),
                    chunk_text_value=chunk_text_value,
                )
            except Exception:  # noqa: BLE001
                logger.exception("failed to write DLQ record file=%s chunk=%s", source_file, chunk_index)
            return ExtractionResult(nodes=[], edges=[])

        fallback = ExtractedEvidence(source_file=source_file, chunk_index=chunk_index, quote=chunk_text_value[:240].strip())
        for node in extracted.nodes:
            if not node.evidence:
                node.evidence = [fallback]
        for edge in extracted.edges:
            if not edge.evidence:
                edge.evidence = [fallback]
        return extracted

    @staticmethod
    def _normalize_only_extensions(only_extensions: list[str] | None) -> frozenset[str] | None:
        """Return normalized suffix set (e.g. {'.yaml'}) or None for \"all supported\"."""
        if not only_extensions:
            return None
        out: set[str] = set()
        for raw in only_extensions:
            e = (raw or "").strip().lower()
            if not e:
                continue
            if not e.startswith("."):
                e = "." + e
            out.add(e)
        if not out:
            return None
        allowed = supported_input_suffixes()
        unknown = out - allowed
        if unknown:
            raise ValueError(f"only_extensions contains unsupported suffixes: {sorted(unknown)}")
        return frozenset(out)

    async def build_graph_from_input(
        self,
        *,
        dry_run: bool = False,
        max_files: int | None = None,
        only_extensions: list[str] | None = None,
    ) -> dict[str, Any]:
        notes: list[str] = []
        if not settings.llm_enabled:
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
        rule_context = read_rule_context_multi(rule_dir)

        failed_files: list[str] = []
        suffix_filter = self._normalize_only_extensions(only_extensions)
        docs = self._collect_input_docs(input_dir, failed_files, suffixes=suffix_filter)
        if max_files is not None and max_files > 0:
            docs = docs[:max_files]
        if suffix_filter is not None:
            notes.append(f"only_extensions={sorted(suffix_filter)} (skipped other input types).")

        logger.info(
            "[%s] [KG] build start dry_run=%s files_total=%s rule_chars=%s only_extensions=%s",
            self._now_str(),
            dry_run,
            len(docs),
            len(rule_context or ""),
            sorted(suffix_filter) if suffix_filter else None,
        )

        raw_nodes: list[ExtractedNode] = []
        raw_edges: list[ExtractedEdge] = []
        files_processed = 0
        chunks_processed = 0
        file_ok_chunks_total = 0
        file_empty_or_failed_chunks_total = 0

        for file_index, (source_file, full_text) in enumerate(docs, start=1):
            chunks = chunk_text(
                full_text,
                chunk_size=settings.kg_chunk_size,
                chunk_overlap=settings.kg_chunk_overlap,
            )
            if not chunks:
                failed_files.append(f"{source_file}: empty_after_chunking")
                logger.warning(
                    "[%s] [KG] file=%s index=%s/%s skipped reason=empty_after_chunking",
                    self._now_str(),
                    source_file,
                    file_index,
                    len(docs),
                )
                continue
            files_processed += 1
            chunks_processed += len(chunks)
            logger.info(
                "[%s] [KG] file=%s index=%s/%s chunks=%s begin",
                self._now_str(),
                source_file,
                file_index,
                len(docs),
                len(chunks),
            )

            # 并发执行 chunk 抽取：吞吐由本地并发 + provider 全局并发双层限制。
            file_nodes, file_edges, file_ok_chunks, file_empty_or_failed_chunks = await self._process_chunks_concurrently(
                source_file=source_file,
                chunks=chunks,
                rule_context=rule_context,
            )
            file_ok_chunks_total += file_ok_chunks
            file_empty_or_failed_chunks_total += file_empty_or_failed_chunks
            raw_nodes.extend(file_nodes)
            raw_edges.extend(file_edges)
            logger.info(
                "[%s] [KG] file=%s index=%s/%s end nodes=%s edges=%s ok_chunks=%s empty_or_failed_chunks=%s",
                self._now_str(),
                source_file,
                file_index,
                len(docs),
                len(file_nodes),
                len(file_edges),
                file_ok_chunks,
                file_empty_or_failed_chunks,
            )

        merged_nodes, merged_edges = self._normalize_and_merge(raw_nodes, raw_edges)
        nodes_payload = [self._node_to_graph_payload(n) for n in merged_nodes.values()]
        edges_payload = [self._edge_to_graph_payload(e) for e in merged_edges.values()]

        if not dry_run and settings.kg_persist_payload_before_merge:
            out_path = Path(settings.kg_merge_payload_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")
            payload_obj = {"nodes": nodes_payload, "edges": edges_payload}
            with tmp_path.open("w", encoding="utf-8") as fp:
                json.dump(payload_obj, fp, ensure_ascii=False)
            tmp_path.replace(out_path)
            logger.info(
                "[%s] [KG] wrote merge payload before Neo4j: path=%s nodes=%s edges=%s",
                self._now_str(),
                out_path,
                len(nodes_payload),
                len(edges_payload),
            )

        if not dry_run:
            repo = get_graph_repository()
            repo.merge_nodes_edges(nodes_payload, edges_payload)

        logger.info(
            "[%s] [KG] build done files_processed=%s files_failed=%s chunks_processed=%s ok_chunks=%s empty_or_failed_chunks=%s nodes_raw=%s edges_raw=%s nodes_merged=%s edges_merged=%s dry_run=%s",
            self._now_str(),
            files_processed,
            len(failed_files),
            chunks_processed,
            file_ok_chunks_total,
            file_empty_or_failed_chunks_total,
            len(raw_nodes),
            len(raw_edges),
            len(nodes_payload),
            len(edges_payload),
            dry_run,
        )

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
        if not v:
            return ""
        # Neo4j 关系类型作标识符时不能以数字开头；避免 MERGE 边时报错
        if v[0].isdigit():
            v = f"rel_{v}"
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

    def _collect_input_docs(
        self,
        input_dir: Path,
        failed_files: list[str],
        *,
        suffixes: frozenset[str] | None = None,
    ) -> list[tuple[str, str]]:
        docs: list[tuple[str, str]] = []
        if not input_dir.exists():
            failed_files.append(f"{str(input_dir)}: input_dir_not_found")
            return docs

        supported = supported_input_suffixes() if suffixes is None else suffixes
        all_files = sorted([p for p in input_dir.iterdir() if p.is_file() and p.suffix.lower() in supported])
        valid_names: set[str] = set()
        for source_file, full_text in iter_input_documents(input_dir, suffixes=suffixes):
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

