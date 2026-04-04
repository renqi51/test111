"""Application configuration — paths resolve relative to backend/ root."""
from pathlib import Path

from dotenv import load_dotenv
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
    llm_api_key: str | None = None
    llm_model_name: str = "gpt-4.1-mini"
    llm_timeout: int = 60

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
    kg_rule_dir: str = str(DATA_DIR / "rule")
    kg_chunk_size: int = 4000
    kg_chunk_overlap: int = 400

    # Authorized lab: DNS + HTTPS reachability (see app/services/probe_service.py)
    probe_enabled: bool = True
    probe_mode: str = "allowlist"  # allowlist | open
    probe_allowlist_suffixes: str = ""
    probe_timeout_sec: float = 5.0
    probe_max_concurrent: int = 8
    probe_verify_tls: bool = True
    probe_tcp_ports: str = "443,80,5060,2152,38412"


settings = Settings()
