from __future__ import annotations

import json
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import settings


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
      "type": "Service|NetworkFunction|Protocol|FQDNPattern|StandardDoc|RiskHypothesis|WorkProduct|Capability|Interface|Platform",
      "description": "简要中文说明",
      "confidence": 0.0-1.0,
      "source_span": "可选，可用原文中的一句话或短片段"
    }
  ],
  "edges": [
    {
      "source": "节点 id",
      "target": "节点 id",
      "interaction": "uses_protocol|uses_network_function|uses_naming_pattern|resolved_via|implemented_via|exposes_interface|governed_by|uses_capability|documented_in|depends_on|has_component|targets|mitigated_by|produces",
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


class OpenAICompatibleProvider(LLMProviderBase):
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
        if not settings.llm_base_url:
            raise RuntimeError("LLM base URL not configured")
        url = settings.llm_base_url.rstrip("/") + "/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
        }
        if settings.llm_api_key:
            headers["Authorization"] = f"Bearer {settings.llm_api_key}"
        payload = {
            "model": model_name or settings.llm_model_name,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        data: dict[str, Any] | None = None
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=settings.llm_timeout) as client:
                    resp = await client.post(url, headers=headers, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    break
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt >= 2:
                    raise
                await asyncio.sleep(0.4 * (attempt + 1))
                continue
            except httpx.HTTPStatusError:
                # 4xx/5xx are returned directly; no blind retry except transient disconnects above.
                raise
        if data is None:
            raise RuntimeError(f"LLM request failed after retries: {last_exc}")
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


def get_llm_provider() -> LLMProviderBase:
    if settings.llm_provider in ("openai", "ollama"):
        return OpenAICompatibleProvider()
    return NullLLMProvider()

