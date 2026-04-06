from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, AsyncIterator

from langchain_milvus import Milvus
from langchain_openai import OpenAIEmbeddings
from pydantic import BaseModel, Field
from pymilvus import MilvusClient
from pymilvus.orm.connections import connections

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.repositories.graph_repository import get_graph_repository

logger = logging.getLogger(__name__)


def _neo4j_node_line(n: dict[str, Any]) -> str:
    """与入库侧 node 文本风格对齐，便于同一套 prompt 消费。"""
    nid = n.get("id", "")
    label = n.get("label", "")
    ntype = n.get("type", "")
    desc = n.get("description", "") or ""
    return f"实体名称: {label}; 实体ID: {nid}; 类型: {ntype}; 描述: {desc}"


def _neo4j_edge_line(e: dict[str, Any]) -> str:
    src = e.get("source", "")
    tgt = e.get("target", "")
    itype = e.get("interaction", "")
    return f"关系: {src} --[{itype}]--> {tgt}"
_MILVUS_CLIENT_PATCHED = False


def _enable_milvus_orm_alias_compat() -> None:
    """为查询路径应用与入库一致的 Milvus ORM alias 兼容补丁。"""
    global _MILVUS_CLIENT_PATCHED
    if _MILVUS_CLIENT_PATCHED:
        return

    original_init = MilvusClient.__init__

    def patched_init(  # type: ignore[no-untyped-def]
        self,
        uri: str = "http://localhost:19530",
        user: str = "",
        password: str = "",
        db_name: str = "",
        token: str = "",
        timeout: float | None = None,
        **kwargs,
    ) -> None:
        alias = str(kwargs.pop("alias", "graph-rag"))
        original_init(
            self,
            uri=uri,
            user=user,
            password=password,
            db_name=db_name,
            token=token,
            timeout=timeout,
            **kwargs,
        )
        try:
            connections.connect(
                alias=alias,
                uri=uri,
                user=user,
                password=password,
                db_name=db_name,
                token=token,
            )
            self._using = alias
        except Exception:  # noqa: BLE001
            pass

    MilvusClient.__init__ = patched_init  # type: ignore[method-assign]
    _MILVUS_CLIENT_PATCHED = True


class GraphRAGAnswerPayload(BaseModel):
    """约束 LLM 回答的 JSON 结构，便于后端稳定处理。"""

    answer: str = Field(default="", description="基于上下文生成的最终答案。")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="回答置信度。")
    citations: list[str] = Field(default_factory=list, description="引用到的 source_file 或片段标识。")
    notes: list[str] = Field(default_factory=list, description="补充说明或不确定性提示。")


class GraphRAGQueryService:
    """
    GraphRAG 问答服务：
    1) （可选）按问题关键字从图存储拉取实时子图（Neo4j 或 file 后端）；
    2) 问题向量化后在 Milvus Top-K 召回（可与 1 组合）；
    3) 图谱上下文优先来自实时子图；原文上下文来自 Milvus chunk；
    4) llm_provider.chat_json 生成最终回答。
    """

    def _resolve_milvus_uri(self) -> str:
        raw = settings.graph_rag_milvus_uri.strip()
        # 支持 Docker/远程 Milvus URI；仅在本地文件模式时做路径归一化。
        if "://" in raw:
            return raw
        path = Path(raw)
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        return str(path)

    def _build_embeddings(self) -> OpenAIEmbeddings:
        api_key = settings.graph_rag_embedding_api_key_value or settings.llm_api_key_value
        base_url = settings.graph_rag_embedding_base_url or settings.llm_base_url
        if not api_key:
            raise RuntimeError("Embedding API key is not configured")
        kwargs: dict[str, Any] = {
            "model": settings.graph_rag_embedding_model,
            "api_key": api_key,
        }
        if base_url:
            kwargs["base_url"] = base_url
        return OpenAIEmbeddings(**kwargs)

    def _build_vector_store(self) -> Milvus:
        _enable_milvus_orm_alias_compat()
        return Milvus(
            embedding_function=self._build_embeddings(),
            collection_name=settings.graph_rag_collection,
            connection_args={"uri": self._resolve_milvus_uri(), "alias": "graph-rag"},
            auto_id=True,
            drop_old=False,
        )

    @staticmethod
    def _to_list_of_str(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(x).strip() for x in value if str(x).strip()]
        text = str(value).strip()
        return [text] if text else []

    @staticmethod
    def _to_confidence(value: Any, default: float = 0.0) -> float:
        try:
            num = float(value)
        except Exception:  # noqa: BLE001
            num = default
        return max(0.0, min(1.0, num))

    def _coerce_answer_payload(
        self,
        raw: dict[str, Any],
        *,
        fallback_citations: list[str] | None = None,
        fallback_notes: list[str] | None = None,
    ) -> GraphRAGAnswerPayload:
        cites = self._to_list_of_str(raw.get("citations"))
        notes = self._to_list_of_str(raw.get("notes"))
        if not cites and fallback_citations:
            cites = list(fallback_citations)
        if not notes and fallback_notes:
            notes = list(fallback_notes)
        return GraphRAGAnswerPayload(
            answer=str(raw.get("answer", "") or ""),
            confidence=self._to_confidence(raw.get("confidence"), default=0.0),
            citations=cites,
            notes=notes,
        )

    async def _retrieve_context(
        self, *, question: str, top_k: int | None = None
    ) -> dict[str, Any]:
        """
        执行 GraphRAG 混合检索问答：
        - “混合”含义：同一次召回内同时使用图谱结构文本（node/edge）与原文文本（chunk）。
        """
        q = question.strip()
        if not q:
            return {"ok": False, "error_payload": {"answer": "", "confidence": 0.0, "citations": [], "notes": ["empty question"]}}
        if not settings.llm_enabled:
            return {"ok": False, "error_payload": {"answer": "", "confidence": 0.0, "citations": [], "notes": ["llm not configured"]}}

        k = max(1, int(top_k or settings.graph_rag_top_k))
        logger.info("[GraphRAG] query begin top_k=%s question_len=%s", k, len(q))

        graph_ctx: list[str] = []
        chunk_ctx: list[str] = []
        citations: list[str] = []
        neo4j_nodes = 0
        neo4j_edges = 0
        neo4j_ok = False
        chunks_only = False

        if settings.graph_rag_neo4j_subgraph_enabled:
            try:
                repo = get_graph_repository()
                sub = repo.subgraph_for_graph_rag_question(
                    q,
                    seed_limit=settings.graph_rag_neo4j_seed_limit,
                    max_edges=settings.graph_rag_neo4j_max_edges,
                )
                neo4j_ok = True
                neo4j_nodes = len(sub.get("nodes", []))
                neo4j_edges = len(sub.get("edges", []))
                for n in sub.get("nodes", []):
                    graph_ctx.append(_neo4j_node_line(n))
                    nid = str(n.get("id", "")).strip()
                    if nid:
                        citations.append(f"neo4j:entity:{nid}")
                for e in sub.get("edges", []):
                    graph_ctx.append(_neo4j_edge_line(e))
                    s, t = str(e.get("source", "")), str(e.get("target", ""))
                    if s and t:
                        citations.append(f"neo4j:rel:{s}->{t}:{e.get('interaction', '')}")
                logger.info(
                    "[GraphRAG] neo4j/file subgraph nodes=%s edges=%s graph_lines=%s",
                    neo4j_nodes,
                    neo4j_edges,
                    len(graph_ctx),
                )
            except Exception:  # noqa: BLE001
                logger.exception("[GraphRAG] subgraph_for_graph_rag_question failed; falling back to Milvus-only graph hints")

        if neo4j_ok and settings.graph_rag_milvus_chunks_only_when_neo4j_context:
            chunks_only = True

        try:
            store = self._build_vector_store()
            # 优先带分数召回，便于后续调参与可观测性。
            try:
                rows = store.similarity_search_with_score(q, k=k)
                docs = [item[0] for item in rows]
            except Exception:
                docs = store.similarity_search(q, k=k)
        except Exception as exc:  # noqa: BLE001
            logger.exception("GraphRAG retrieval failed: err=%s", str(exc)[:220])
            return {
                "ok": False,
                "error_payload": {
                    "answer": "",
                    "confidence": 0.0,
                    "citations": [],
                    "notes": [f"retrieval failed: {str(exc)[:180]}"],
                },
            }

        milvus_graph_lines = 0
        for doc in docs:
            md = doc.metadata or {}
            dtype = str(md.get("type", "")).strip().lower()
            source_file = str(md.get("source_file", "")).strip()
            chunk_index = md.get("chunk_index")
            cite = f"{source_file}#chunk-{chunk_index}" if source_file and chunk_index is not None else source_file
            if cite:
                citations.append(cite)

            content = doc.page_content.strip()
            if not content:
                continue
            if dtype in {"node", "edge"}:
                if chunks_only:
                    milvus_graph_lines += 1
                    continue
                graph_ctx.append(content)
            else:
                chunk_ctx.append(content)

        if milvus_graph_lines:
            logger.info(
                "[GraphRAG] skipped %s Milvus node/edge hits (chunks_only_when_neo4j_context=%s)",
                milvus_graph_lines,
                chunks_only,
            )

        # 去重并限制长度，避免 prompt 过长导致成本和时延飙升。
        graph_ctx = list(dict.fromkeys(graph_ctx))[:50]
        chunk_ctx = list(dict.fromkeys(chunk_ctx))[:30]
        citations = list(dict.fromkeys(citations))[:30]

        logger.info(
            "[GraphRAG] query retrieved raw_docs=%s graph_ctx=%s chunk_ctx=%s neo4j_subgraph_ok=%s chunks_only=%s",
            len(docs),
            len(graph_ctx),
            len(chunk_ctx),
            neo4j_ok,
            chunks_only,
        )
        return {
            "ok": True,
            "question": q,
            "k": k,
            "graph_ctx": graph_ctx,
            "chunk_ctx": chunk_ctx,
            "citations": citations,
        }

    async def ask(self, *, question: str, top_k: int | None = None) -> dict[str, Any]:
        """
        执行 GraphRAG 混合检索问答：
        - “混合”含义：同一次召回内同时使用图谱结构文本（node/edge）与原文文本（chunk）。
        """
        prep = await self._retrieve_context(question=question, top_k=top_k)
        if not prep.get("ok"):
            return prep["error_payload"]
        q = str(prep["question"])
        graph_ctx = list(prep["graph_ctx"])
        chunk_ctx = list(prep["chunk_ctx"])
        citations = list(prep["citations"])

        system_prompt = (
            "你是 GraphRAG 问答助手。"
            "必须严格基于提供的“图谱上下文”（可含实时图数据库子图）和“原文上下文”（向量库召回的文档切块）回答，不得编造。"
            "输出 JSON，字段为 answer/confidence/citations/notes。"
        )
        user_prompt = (
            f"用户问题:\n{q}\n\n"
            f"核心实体与关系图谱上下文（来自当前图存储子图 + 可选向量召回）:\n"
            + ("\n".join(f"- {x}" for x in graph_ctx) if graph_ctx else "- (none)")
            + "\n\n"
            f"详细参考原文上下文:\n" + ("\n".join(f"- {x}" for x in chunk_ctx) if chunk_ctx else "- (none)") + "\n\n"
            "要求:\n"
            "1) 仅基于上面上下文作答；\n"
            "2) 如果证据不足，请明确说明；\n"
            "3) citations 优先引用 source_file#chunk-index。\n"
        )

        try:
            llm_res = await get_llm_provider().chat_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model_name=settings.llm_model_name,
                temperature=0.1,
            )
            payload = self._coerce_answer_payload(
                llm_res.raw if isinstance(llm_res.raw, dict) else {},
                fallback_citations=citations,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("GraphRAG LLM answer failed: err=%s", str(exc)[:220])
            return {
                "answer": "",
                "confidence": 0.0,
                "citations": citations,
                "notes": [f"llm answer failed: {str(exc)[:180]}"],
            }

        logger.info("[GraphRAG] query done answer_chars=%s", len(payload.answer or ""))
        return payload.model_dump()

    async def ask_stream(self, *, question: str, top_k: int | None = None) -> AsyncIterator[dict[str, Any]]:
        prep = await self._retrieve_context(question=question, top_k=top_k)
        if not prep.get("ok"):
            yield {"type": "final", "payload": prep["error_payload"]}
            return

        q = str(prep["question"])
        graph_ctx = list(prep["graph_ctx"])
        chunk_ctx = list(prep["chunk_ctx"])
        citations = list(prep["citations"])

        stream_system_prompt = (
            "你是 GraphRAG 问答助手。"
            "你必须仅基于提供的图谱上下文和原文上下文回答，避免编造。"
            "请直接输出自然语言答案正文，不要输出 JSON。"
        )
        stream_user_prompt = (
            f"用户问题:\n{q}\n\n"
            f"核心实体与关系图谱上下文:\n"
            + ("\n".join(f"- {x}" for x in graph_ctx) if graph_ctx else "- (none)")
            + "\n\n"
            f"详细参考原文上下文:\n"
            + ("\n".join(f"- {x}" for x in chunk_ctx) if chunk_ctx else "- (none)")
            + "\n\n"
            "要求:\n"
            "1) 只基于上下文回答；\n"
            "2) 若证据不足，请明确说明。\n"
        )

        answer_parts: list[str] = []
        try:
            async for delta in get_llm_provider().chat_stream_text(
                system_prompt=stream_system_prompt,
                user_prompt=stream_user_prompt,
                model_name=settings.llm_model_name,
                temperature=0.1,
            ):
                if delta:
                    answer_parts.append(delta)
                    yield {"type": "delta", "delta": delta}
        except Exception as exc:  # noqa: BLE001
            logger.exception("GraphRAG stream failed: err=%s", str(exc)[:220])
            yield {"type": "error", "error": f"graph-rag stream failed: {str(exc)[:180]}"}
            return

        answer = "".join(answer_parts).strip()
        if not answer:
            answer = "未生成有效回答。请调整问题或检查上下文召回质量。"
        payload = GraphRAGAnswerPayload(
            answer=answer,
            confidence=0.65 if citations else 0.45,
            citations=citations,
            notes=[] if citations else ["limited evidence context"],
        )
        yield {"type": "final", "payload": payload.model_dump()}


_graph_rag_query_service: GraphRAGQueryService | None = None


def get_graph_rag_query_service() -> GraphRAGQueryService:
    global _graph_rag_query_service
    if _graph_rag_query_service is None:
        _graph_rag_query_service = GraphRAGQueryService()
    return _graph_rag_query_service

