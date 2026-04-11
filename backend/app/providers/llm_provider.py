from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import httpx
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings

logger = logging.getLogger(__name__)

# 仅对这些状态码做重试，避免对客户端错误进行无意义重试。
RETRYABLE_HTTP_STATUS = {429, 502, 503, 504}
NON_RETRYABLE_HTTP_STATUS = {400, 401, 403, 404}
# 全局并发闸门：限制同时在途的 LLM 请求数，避免上游被突发流量压垮。
_LLM_REQUEST_SEMAPHORE = asyncio.Semaphore(max(1, int(settings.llm_max_concurrency)))


@dataclass
class LLMExtractResult:
    raw: dict[str, Any]
    model: str
    provider: str
    created_at: str


class LLMProviderBase(ABC):
    @abstractmethod
    async def extract_structured(self, text: str) -> LLMExtractResult: ...

    @abstractmethod
    async def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        model_name: str | None = None,
        temperature: float = 0.2,
    ) -> LLMExtractResult: ...

    @abstractmethod
    async def chat_stream_text(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        model_name: str | None = None,
        temperature: float = 0.2,
    ) -> AsyncIterator[str]: ...


class RetryableHTTPStatusError(RuntimeError):
    """包装可重试 HTTP 状态错误，供 tenacity 识别。"""

    def __init__(self, status_code: int, body_preview: str = "") -> None:
        super().__init__(f"Retryable HTTP status={status_code}, body={body_preview}")
        self.status_code = status_code
        self.body_preview = body_preview


def _before_retry_log(retry_state: RetryCallState) -> None:
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    logger.warning(
        "LLM request retrying: attempt=%s err=%s",
        retry_state.attempt_number,
        str(exc)[:220] if exc else "(unknown)",
    )


SYSTEM_PROMPT = """你是一名安全研究助理，专注 3GPP / GSMA / 运营商开放网络标准。
给你一段【标准/官方文档/技术说明】的【概括性中文或英文文本】，请只做结构化知识抽取：

- 识别：服务（VoWiFi, IMS, RCS, Open Gateway 等）
- 识别：网元（ePDG, N3IWF, P-CSCF, I-CSCF, S-CSCF 等）
- 识别：协议（SIP, DNS, IKEv2, IPsec, HTTPS, REST 等）
- 识别：FQDN 模式（含 mnc/mcc/3gppnetwork.org 等）
- 识别：标准文档（如 3GPP TS 23.003, TS 24.502, TS 23.228, TS 24.229, GSMA Open Gateway, CAMARA Commonalities）
- 识别：风险线索（但不要输出攻击方案，只描述“风险假设”级别）
- 识别：上述实体之间的候选关系（uses_protocol, uses_network_function, uses_naming_pattern, documented_in, implemented_via, resolved_via, targets 等）

必须以 JSON 返回，格式为：
{
  "nodes": [
    {
      "id": "string (建议可稳定复用的 id，如 svc_ims, nf_epdg 等；若不确定可用 slug)",
      "label": "短标签",
      "type": "Service|NetworkFunction|Protocol|FQDNPattern|StandardDoc|RiskHypothesis|WorkProduct|Capability|Interface|Platform|Vulnerability|ThreatVector",
      "description": "简要中文说明",
      "confidence": 0.0-1.0,
      "source_span": "可选，可用原文中的一句话或短片段"
    }
  ],
  "edges": [
    {
      "source": "节点 id",
      "target": "节点 id",
      "interaction": "uses_protocol|uses_network_function|uses_naming_pattern|resolved_via|implemented_via|exposes_interface|governed_by|uses_capability|documented_in|depends_on|has_component|targets|mitigated_by|produces|vulnerable_to|enables_vector",
      "confidence": 0.0-1.0,
      "evidence": "简短中文说明"
    }
  ],
  "risk_hypotheses": [
    {
      "label": "风险假设概述",
      "description": "简单说明",
      "confidence": 0.0-1.0
    }
  ],
  "notes": [
    "可选的补充说明数组"
  ]
}

要求：
- 严格输出合法 JSON，不要包含注释或额外解释。
- 如果你不确定，请降低 confidence，而不是编造细节。
- 不要输出任何攻击建议或利用步骤。
"""


def _resolve_chat_completions_url() -> str:
    custom_url = (settings.llm_chat_completions_url or "").strip()
    if custom_url:
        if not custom_url.startswith(("http://", "https://")):
            raise RuntimeError("EXPOSURE_LLM_CHAT_COMPLETIONS_URL must start with http:// or https://")
        return custom_url

    base_url = (settings.llm_base_url or "").strip()
    if not base_url:
        raise RuntimeError("LLM base URL not configured")
    if not base_url.startswith(("http://", "https://")):
        raise RuntimeError("EXPOSURE_LLM_BASE_URL must start with http:// or https://")
    # Accept both host-only base URL and OpenAI-style /v1 base URL.
    normalized = base_url.rstrip("/")
    if normalized.endswith("/v1"):
        return normalized + "/chat/completions"
    return normalized + "/v1/chat/completions"


class OpenAICompatibleProvider(LLMProviderBase):
    @retry(
        stop=stop_after_attempt(max(1, int(settings.llm_retry_attempts))),
        wait=wait_exponential(
            multiplier=1,
            min=max(1, int(settings.llm_retry_min_wait_sec)),
            max=max(1, int(settings.llm_retry_max_wait_sec)),
        ),
        retry=retry_if_exception_type(
            (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.TransportError,
                RetryableHTTPStatusError,
            )
        ),
        before_sleep=_before_retry_log,
        reraise=True,
    )
    async def _post_chat_with_retry(
        self,
        *,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        # 全局并发闸门：将所有入口统一纳入限流控制。
        async with _LLM_REQUEST_SEMAPHORE:
            try:
                async with httpx.AsyncClient(timeout=settings.llm_timeout, follow_redirects=True) as client:
                    resp = await client.post(url, headers=headers, json=payload)
            except (httpx.TimeoutException, httpx.ConnectError, httpx.TransportError):
                # 交给 tenacity 判定并重试。
                raise

        if resp.status_code >= 400:
            body_preview = (resp.text or "")[:240]
            # 429/502/503/504 属于瞬态故障，交给 tenacity 自动退避重试。
            if resp.status_code in RETRYABLE_HTTP_STATUS:
                raise RetryableHTTPStatusError(resp.status_code, body_preview=body_preview)
            # 明确的客户端参数/权限问题直接失败，不重试。
            if resp.status_code in NON_RETRYABLE_HTTP_STATUS:
                resp.raise_for_status()
            # 其他未知状态码默认按不可恢复处理，避免无限放大请求风暴。
            resp.raise_for_status()

        return resp.json()

    async def extract_structured(self, text: str) -> LLMExtractResult:
        return await self.chat_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=f"请基于下面这段文本进行抽取并返回 JSON：\n\n{text}",
            model_name=settings.llm_model_name,
            temperature=0.2,
        )

    async def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        model_name: str | None = None,
        temperature: float = 0.2,
    ) -> LLMExtractResult:
        url = _resolve_chat_completions_url()
        headers = {
            "Content-Type": "application/json",
        }
        llm_api_key = settings.llm_api_key_value
        if llm_api_key:
            headers["Authorization"] = f"Bearer {llm_api_key}"
        model_used = model_name or settings.llm_model_name
        payload = {
            "model": model_used,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        logger.debug(
            "LLM chat_json request model=%s system_chars=%s user_chars=%s",
            model_used,
            len(system_prompt),
            len(user_prompt),
        )
        data = await self._post_chat_with_retry(url=url, headers=headers, payload=payload)
        content = data["choices"][0]["message"]["content"]
        try:
            parsed = json.loads(content)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"LLM 返回的不是合法 JSON: {content!r}") from exc
        return LLMExtractResult(
            raw=parsed,
            model=data.get("model", settings.llm_model_name),
            provider=settings.llm_provider or "openai-compatible",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def chat_stream_text(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        model_name: str | None = None,
        temperature: float = 0.2,
    ) -> AsyncIterator[str]:
        url = _resolve_chat_completions_url()
        headers = {"Content-Type": "application/json"}
        llm_api_key = settings.llm_api_key_value
        if llm_api_key:
            headers["Authorization"] = f"Bearer {llm_api_key}"
        model_used = model_name or settings.llm_model_name
        payload = {
            "model": model_used,
            "temperature": temperature,
            "stream": True,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        async with _LLM_REQUEST_SEMAPHORE:
            async with httpx.AsyncClient(timeout=settings.llm_timeout, follow_redirects=True) as client:
                async with client.stream("POST", url, headers=headers, json=payload) as resp:
                    if resp.status_code >= 400:
                        body_preview = (await resp.aread()).decode("utf-8", errors="ignore")[:240]
                        raise RuntimeError(f"LLM stream failed status={resp.status_code} body={body_preview}")
                    async for line in resp.aiter_lines():
                        s = (line or "").strip()
                        if not s:
                            continue
                        if not s.startswith("data:"):
                            continue
                        data = s[5:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            obj = json.loads(data)
                        except Exception:  # noqa: BLE001
                            continue
                        choices = obj.get("choices") or []
                        if not choices:
                            continue
                        delta = choices[0].get("delta") or {}
                        content = delta.get("content")
                        if isinstance(content, str) and content:
                            yield content


class NullLLMProvider(LLMProviderBase):
    async def extract_structured(self, text: str) -> LLMExtractResult:  # noqa: ARG002
        return LLMExtractResult(
            raw={"nodes": [], "edges": [], "risk_hypotheses": [], "notes": ["llm disabled"]},
            model="none",
            provider="disabled",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def chat_json(
        self,
        system_prompt: str,  # noqa: ARG002
        user_prompt: str,  # noqa: ARG002
        *,
        model_name: str | None = None,  # noqa: ARG002
        temperature: float = 0.2,  # noqa: ARG002
    ) -> LLMExtractResult:
        return LLMExtractResult(
            raw={"notes": ["llm disabled"], "states": [], "transitions": []},
            model="none",
            provider="disabled",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def chat_stream_text(
        self,
        system_prompt: str,  # noqa: ARG002
        user_prompt: str,  # noqa: ARG002
        *,
        model_name: str | None = None,  # noqa: ARG002
        temperature: float = 0.2,  # noqa: ARG002
    ) -> AsyncIterator[str]:
        if False:
            yield ""


def get_llm_provider() -> LLMProviderBase:
    if settings.llm_provider in ("openai", "ollama"):
        return OpenAICompatibleProvider()
    return NullLLMProvider()

