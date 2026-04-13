"""Application configuration — paths resolve relative to backend/ root."""
from pathlib import Path

from dotenv import load_dotenv
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_ROOT / "data"
SEED_DIR = DATA_DIR / "seed"
RUNTIME_DIR = DATA_DIR / "runtime"

# Load .env if present (optional). Settings reads from environment variables after this.
load_dotenv(BACKEND_ROOT / ".env", override=False)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EXPOSURE_", extra="ignore")

    app_name: str = "3GPP Open Exposure Demo API"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # graph backend: "neo4j" or "file"
    graph_backend: str = "neo4j"

    # Neo4j connection
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    # LLM provider (OpenAI-compatible / Ollama-style)
    llm_provider: str | None = None  # "openai" | "ollama" | None
    llm_base_url: str | None = None
    # Optional full endpoint URL. If set, this value is used as-is without auto-joining.
    llm_chat_completions_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_model_name: str = "gpt-4.1-mini"
    # httpx 读超时（秒）；ReAct / GraphRAG 单次 prompt 较大，60 易触发上游断开或 ReadTimeout
    llm_timeout: int = 180
    llm_max_concurrency: int = 4
    llm_retry_attempts: int = 5
    llm_retry_min_wait_sec: int = 2
    llm_retry_max_wait_sec: int = 30

    # Extraction pipeline
    extraction_worker_model: str = "gpt-4.1-mini"
    extraction_judge_model: str = "gpt-4.1-mini"
    extraction_budget_mode: str = "default"  # default | high_precision
    extraction_evidence_top_k: int = 10
    extraction_evidence_top_k_high_precision: int = 14
    extraction_retrieval_strategy: str = "keyword_overlap"  # keyword_overlap | bm25 | vector
    extraction_rerank_enabled: bool = False
    extraction_rerank_strategy: str = "noop"
    extraction_enable_repair: bool = True
    extraction_max_repair_rounds: int = 1
    extraction_low_score_threshold: float = 0.65
    extraction_conflict_threshold: int = 3
    extraction_staging_backend: str = "file"  # file | neo4j
    extraction_runtime_path: str = str(RUNTIME_DIR)
    extraction_prompt_override_path: str = str(RUNTIME_DIR / "prompt_overrides.json")
    extraction_enable_local_compatible_endpoint: bool = True

    # Local KG builder
    kg_input_dir: str = str(DATA_DIR / "input")
    # Primary rules dir; code also merges sibling ``data/rules`` if it exists (read_rule_context_multi).
    kg_rule_dir: str = str(DATA_DIR / "rule")
    kg_chunk_size: int = 4000
    kg_chunk_overlap: int = 400

    # GraphRAG (Milvus Lite + Embeddings)
    graph_rag_milvus_uri: str = str(DATA_DIR / "milvus_graph_rag.db")
    graph_rag_collection: str = "graph_rag_docs"
    graph_rag_embedding_model: str = "text-embedding-3-small"
    graph_rag_top_k: int = 15
    # 若未单独配置，则默认复用 llm_base_url / llm_api_key
    graph_rag_embedding_base_url: str | None = None
    graph_rag_embedding_api_key: SecretStr | None = None
    graph_rag_embedding_request_timeout: int = 60
    graph_rag_embedding_max_retries: int = 5
    graph_rag_ingest_batch_size: int = 80
    graph_rag_ingest_batch_sleep_sec: float = 0.5
    # GraphRAG 问答：除 Milvus 外是否实时查 Neo4j（或 file 后端的全量图）补「图谱上下文」
    graph_rag_neo4j_subgraph_enabled: bool = True
    graph_rag_neo4j_seed_limit: int = 20
    graph_rag_neo4j_max_edges: int = 100
    # 启用上图谱补全后，Milvus 侧只把 chunk 当「原文上下文」，避免与 Neo4j 中重复 node/edge 向量
    graph_rag_milvus_chunks_only_when_neo4j_context: bool = True

    # KG 构建并发与死信日志
    kg_builder_chunk_concurrency: int = 4
    kg_builder_dlq_path: str = str(RUNTIME_DIR / "kg_chunk_failures.jsonl")
    # 合并进 Neo4j 之前落盘全量 nodes/edges（防止 merge 失败导致只能重抽）。大任务 JSON 可能较大。
    kg_persist_payload_before_merge: bool = True
    kg_merge_payload_path: str = str(RUNTIME_DIR / "kg_last_merge_payload.json")

    @staticmethod
    def _secret_value(value: SecretStr | None) -> str | None:
        if value is None:
            return None
        raw = value.get_secret_value().strip()
        return raw or None

    @staticmethod
    def mask_secret(value: str | None, *, prefix: int = 6, suffix: int = 4) -> str:
        if not value:
            return "(empty)"
        if len(value) <= prefix + suffix:
            return "*" * len(value)
        return f"{value[:prefix]}{'*' * (len(value) - prefix - suffix)}{value[-suffix:]}"

    @property
    def llm_api_key_value(self) -> str | None:
        return self._secret_value(self.llm_api_key)

    @property
    def graph_rag_embedding_api_key_value(self) -> str | None:
        return self._secret_value(self.graph_rag_embedding_api_key)

    @property
    def llm_api_key_masked(self) -> str:
        return self.mask_secret(self.llm_api_key_value)

    @property
    def graph_rag_embedding_api_key_masked(self) -> str:
        return self.mask_secret(self.graph_rag_embedding_api_key_value)

    @property
    def llm_has_endpoint(self) -> bool:
        full_url = (self.llm_chat_completions_url or "").strip()
        base_url = (self.llm_base_url or "").strip()
        return bool(full_url or base_url)

    @property
    def llm_enabled(self) -> bool:
        provider = (self.llm_provider or "").strip()
        return bool(provider and self.llm_has_endpoint)

    # Authorized lab: DNS + HTTPS reachability (see app/services/probe_service.py)
    probe_enabled: bool = True
    probe_mode: str = "allowlist"  # allowlist | open
    probe_allowlist_suffixes: str = ""
    probe_timeout_sec: float = 5.0
    probe_max_concurrent: int = 8
    probe_verify_tls: bool = True
    probe_tcp_ports: str = "443,80,5060,2152,38412"
    # Comma-separated CIDRs; allowlist 模式下字面 IP（含 127.0.0.1、网元 IP）必须落在此列表，否则探测与沙箱会跳过。
    probe_allowlist_cidrs: str = ""

    # Exposure: local spec corpus for 3GPP/GSMA retrieval (optional; see spec_context_service)
    exposure_spec_docs_path: str = str(DATA_DIR / "specs")
    exposure_evidence_top_k: int = 5
    # Outside-in exposure: max hosts materialized from all CIDR inputs per analyze/generate call.
    exposure_max_cidr_expand_hosts: int = 512

    # exploit_sandbox_service: subprocess wall-clock 与输出截断（防止失控长任务与大 stdout）
    exploit_sandbox_timeout_sec: float = 15.0
    exploit_sandbox_max_output_chars: int = 8000


settings = Settings()
