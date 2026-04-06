from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from langchain_milvus import Milvus
from langchain_openai import OpenAIEmbeddings
from pydantic import BaseModel, Field

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider

logger = logging.getLogger(__name__)


class GraphRAGAnswerPayload(BaseModel):
    """约束 LLM 回答的 JSON 结构，便于后端稳定处理。"""

    answer: str = Field(default="", description="基于上下文生成的最终答案。")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="回答置信度。")
    citations: list[str] = Field(default_factory=list, description="引用到的 source_file 或片段标识。")
    notes: list[str] = Field(default_factory=list, description="补充说明或不确定性提示。")


class GraphRAGQueryService:
    """
    GraphRAG 问答服务：
    1) 问题向量化；
    2) Milvus Top-K 召回；
    3) 按 metadata.type 分类图谱上下文与原文上下文；
    4) 复用现有 llm_provider.chat_json 生成最终回答。
    """

    def _resolve_milvus_uri(self) -> str:
        path = Path(settings.graph_rag_milvus_uri)
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
        return Milvus(
            embedding_function=self._build_embeddings(),
            collection_name=settings.graph_rag_collection,
            connection_args={"uri": self._resolve_milvus_uri()},
            auto_id=True,
            drop_old=False,
        )

    async def ask(self, *, question: str, top_k: int | None = None) -> dict[str, Any]:
        """
        执行 GraphRAG 混合检索问答：
        - “混合”含义：同一次召回内同时使用图谱结构文本（node/edge）与原文文本（chunk）。
        """
        q = question.strip()
        if not q:
            return {"answer": "", "confidence": 0.0, "citations": [], "notes": ["empty question"]}
        if not settings.llm_enabled:
            return {"answer": "", "confidence": 0.0, "citations": [], "notes": ["llm not configured"]}

        k = max(1, int(top_k or settings.graph_rag_top_k))
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
            return {"answer": "", "confidence": 0.0, "citations": [], "notes": [f"retrieval failed: {str(exc)[:180]}"]}

        graph_ctx: list[str] = []
        chunk_ctx: list[str] = []
        citations: list[str] = []

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
                graph_ctx.append(content)
            else:
                chunk_ctx.append(content)

        # 去重并限制长度，避免 prompt 过长导致成本和时延飙升。
        graph_ctx = list(dict.fromkeys(graph_ctx))[:50]
        chunk_ctx = list(dict.fromkeys(chunk_ctx))[:30]
        citations = list(dict.fromkeys(citations))[:30]

        system_prompt = (
            "你是 GraphRAG 问答助手。"
            "必须严格基于提供的“图谱上下文”和“原文上下文”回答，不得编造。"
            "输出 JSON，字段为 answer/confidence/citations/notes。"
        )
        user_prompt = (
            f"用户问题:\n{q}\n\n"
            f"核心实体与关系图谱上下文:\n" + ("\n".join(f"- {x}" for x in graph_ctx) if graph_ctx else "- (none)") + "\n\n"
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
            payload = GraphRAGAnswerPayload.model_validate(llm_res.raw)
        except Exception as exc:  # noqa: BLE001
            logger.exception("GraphRAG LLM answer failed: err=%s", str(exc)[:220])
            return {
                "answer": "",
                "confidence": 0.0,
                "citations": citations,
                "notes": [f"llm answer failed: {str(exc)[:180]}"],
            }

        # 如果模型未主动填 citations，后端补充召回来源，保证可追踪。
        if not payload.citations:
            payload.citations = citations
        return payload.model_dump()


_graph_rag_query_service: GraphRAGQueryService | None = None


def get_graph_rag_query_service() -> GraphRAGQueryService:
    global _graph_rag_query_service
    if _graph_rag_query_service is None:
        _graph_rag_query_service = GraphRAGQueryService()
    return _graph_rag_query_service

