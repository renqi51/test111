"""
Rule-based entity/relation extraction + LLM-assisted hybrid extraction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.schemas.extract import (
    CandidateEdge,
    CandidateNode,
    ExtractResponse,
    HybridExtractResponse,
    LLMExtractPayload,
)
from app.providers.llm_provider import get_llm_provider


# Fixed keyword → canonical graph id (must exist in seed or will be created on merge)
KEYWORD_NODES: list[tuple[str, str, str, str, str]] = [
    # (regex or literal match key, id, label, type, description)
    (r"\bVoWiFi\b", "svc_vowifi", "VoWiFi", "Service", "Wi-Fi 接入的运营商语音业务"),
    (r"\bIMS\b", "svc_ims", "IMS", "Service", "IP 多媒体子系统"),
    (r"\bRCS\b", "svc_rcs", "RCS", "Service", "富通信套件业务"),
    (r"Open Gateway", "svc_open_gateway", "Open Gateway", "Service", "运营商开放网络能力框架"),
    (r"\bePDG\b", "nf_epdg", "ePDG", "NetworkFunction", "非可信 Wi-Fi 接入网关"),
    (r"\bN3IWF\b", "nf_n3iwf", "N3IWF", "NetworkFunction", "5G 非 3GPP 接入互通"),
    (r"P-CSCF", "nf_pcscf", "P-CSCF", "NetworkFunction", "代理呼叫会话控制功能"),
    (r"I-CSCF", "nf_icscf", "I-CSCF", "NetworkFunction", "查询呼叫会话控制功能"),
    (r"S-CSCF", "nf_scscf", "S-CSCF", "NetworkFunction", "服务呼叫会话控制功能"),
    (r"\bSIP\b", "proto_sip", "SIP", "Protocol", "会话初始协议"),
    (r"\bDNS\b", "proto_dns", "DNS", "Protocol", "域名解析"),
    (r"IKEv2", "proto_ikev2", "IKEv2", "Protocol", "互联网密钥交换 v2"),
    (r"\bIPsec\b", "proto_ipsec", "IPsec", "Protocol", "IP 层安全协议族"),
    (r"\bHTTPS\b", "proto_https", "HTTPS", "Protocol", "TLS 承载 HTTP"),
    (r"\bREST\b", "proto_rest", "REST", "Protocol", "表述性状态转移风格 API"),
    (r"CAMARA Commonalities", "plat_camara_common", "CAMARA Commonalities", "Platform", "CAMARA 共性规范与基线"),
    (r"\bCAMARA\b", "plat_camara", "CAMARA", "Platform", "电信能力开放 API 项目"),
    (r"Identity\s*&\s*Consent|身份与同意|ICM", "cap_icm", "Identity & Consent Management", "Capability", "身份与同意管理相关能力"),
    (r"northbound|北向", "iface_nb_api", "Northbound Network API", "Interface", "面向第三方的北向网络能力接口"),
    (r"TS\s*23\.003", "doc_ts23003", "3GPP TS 23.003", "StandardDoc", "编号与寻址"),
    (r"TS\s*24\.502", "doc_ts24502", "3GPP TS 24.502", "StandardDoc", "非 3GPP 接入相关流程"),
    (r"TS\s*23\.228", "doc_ts23228", "3GPP TS 23.228", "StandardDoc", "IMS 描述"),
    (r"TS\s*24\.229", "doc_ts24229", "3GPP TS 24.229", "StandardDoc", "IMS SIP 与 SDP"),
    (r"GSMA\s+Open\s+Gateway", "doc_gsma_og", "GSMA Open Gateway", "StandardDoc", "GSMA 开放网关倡议说明"),
]

FQDN_PATTERN_RE = re.compile(
    r"[\w.-]*mnc\s*<\s*MNC\s*>[\w.-]*mcc\s*<\s*MCC\s*>[\w.-]*3gppnetwork\.org",
    re.IGNORECASE,
)
FQDN_ALT_RE = re.compile(
    r"[\w.]+\.mnc\d{2,3}\.mcc\d{3}\.[\w.]+\.3gppnetwork\.org",
    re.IGNORECASE,
)

# Co-occurrence rules: (type_a, type_b) not used — use id sets
COEDGE_RULES: list[tuple[str, str, str, str, str]] = [
    ("svc_ims", "proto_sip", "uses_protocol", "IMS 与 SIP 共现"),
    ("svc_open_gateway", "plat_camara", "implemented_via", "Open Gateway 与 CAMARA 共现"),
    ("nf_epdg", "proto_dns", "resolved_via", "ePDG 与 DNS 共现"),
    ("nf_epdg", "proto_ikev2", "uses_protocol", "ePDG 与 IKEv2 共现"),
    ("svc_vowifi", "proto_ikev2", "uses_protocol", "VoWiFi 与 IKEv2 共现"),
    ("svc_vowifi", "nf_epdg", "uses_network_function", "VoWiFi 与 ePDG 共现"),
    ("nf_n3iwf", "proto_dns", "resolved_via", "N3IWF 与 DNS 共现"),
]


@dataclass
class RuleExtractResult:
    nodes: list[CandidateNode]
    edges: list[CandidateEdge]
    patterns: list[str]


def _confidence(hit_count: int) -> float:
    return min(1.0, 0.5 + 0.1 * hit_count)


def extract_rule_based(text: str) -> RuleExtractResult:
    patterns: list[str] = []
    found_ids: set[str] = set()
    nodes: list[CandidateNode] = []

    for pat, nid, label, ntype, desc in KEYWORD_NODES:
        if re.search(pat, text, re.IGNORECASE):
            if nid not in found_ids:
                found_ids.add(nid)
                nodes.append(
                    CandidateNode(
                        id=nid,
                        label=label,
                        type=ntype,
                        description=desc,
                        evidence_source="关键词规则",
                        en_identifier=nid,
                        confidence=_confidence(1),
                    )
                )
                patterns.append(f"keyword:{pat}")

    if FQDN_PATTERN_RE.search(text) or FQDN_ALT_RE.search(text) or "3gppnetwork.org" in text.lower():
        patterns.append("fqdn_template")
        if "fqdn_pattern_generic" not in found_ids:
            found_ids.add("fqdn_pattern_generic")
            nodes.append(
                CandidateNode(
                    id="fqdn_pattern_generic",
                    label="3GPP FQDN 模板（抽取）",
                    type="FQDNPattern",
                    description="文本中出现符合 3GPP 风格的 FQDN 命名模板或实例",
                    evidence_source="正则规则",
                    en_identifier="*.mnc<MNC>.mcc<MCC>.*.3gppnetwork.org",
                    confidence=0.72,
                )
            )

    edges: list[CandidateEdge] = []
    for a, b, rel, _ in COEDGE_RULES:
        if a in found_ids and b in found_ids:
            edges.append(
                CandidateEdge(source=a, target=b, interaction=rel, confidence=0.78)
            )
            patterns.append(f"cooccur:{a}->{b}")

    # IMS + SIP explicit
    if "svc_ims" in found_ids and "proto_sip" in found_ids:
        if not any(e.source == "svc_ims" and e.target == "proto_sip" for e in edges):
            edges.append(
                CandidateEdge(source="svc_ims", target="proto_sip", interaction="uses_protocol", confidence=0.9)
            )

    # FQDN pattern + TS 23.003
    if "fqdn_pattern_generic" in found_ids and "doc_ts23003" in found_ids:
        edges.append(
            CandidateEdge(
                source="fqdn_pattern_generic",
                target="doc_ts23003",
                interaction="documented_in",
                confidence=0.7,
            )
        )
        patterns.append("fqdn+ts23003")

    # Specific FQDN subtype nodes if keywords present
    if "ims" in text.lower() and "mnc" in text.lower() and "3gppnetwork.org" in text.lower():
        if "fqdn_ims" not in found_ids:
            found_ids.add("fqdn_ims")
            nodes.append(
                CandidateNode(
                    id="fqdn_ims",
                    label="IMS APN/FQDN 模式",
                    type="FQDNPattern",
                    description="ims.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org",
                    evidence_source="上下文规则",
                    en_identifier="ims.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org",
                    confidence=0.68,
                )
            )

    return RuleExtractResult(nodes=nodes, edges=edges, patterns=patterns)


async def extract_llm(text: str) -> LLMExtractPayload | None:
    """Call configured LLM provider and validate JSON payload."""
    # If LLM is not configured, treat as disabled and fallback to rule.
    if not settings.llm_enabled:
        return None
    provider = get_llm_provider()
    res = await provider.extract_structured(text)
    # Validate with Pydantic schema
    try:
        payload = LLMExtractPayload.model_validate(res.raw)
    except Exception:
        # 不信任不合法输出，直接返回 None，由上层 fallback 到规则结果
        return None
    return payload


def to_extract_response(rule: RuleExtractResult) -> ExtractResponse:
    return ExtractResponse(nodes=rule.nodes, edges=rule.edges, matched_patterns=rule.patterns)


def merge_rule_and_llm(rule: RuleExtractResult, llm: LLMExtractPayload | None) -> ExtractResponse:
    """简单合并规则与 LLM 结果，基本去重。"""
    nodes: dict[str, CandidateNode] = {n.id: n for n in rule.nodes}
    edges: set[tuple[str, str, str]] = {(e.source, e.target, e.interaction) for e in rule.edges}
    merged_edges: list[CandidateEdge] = list(rule.edges)

    if llm:
        for n in llm.nodes:
            if n.id not in nodes:
                nodes[n.id] = CandidateNode(
                    id=n.id,
                    label=n.label,
                    type=n.type,
                    description=n.description,
                    evidence_source="LLM 抽取",
                    en_identifier=n.id,
                    confidence=n.confidence,
                )
        for e in llm.edges:
            key = (e.source, e.target, e.interaction)
            if key in edges:
                continue
            merged_edges.append(
                CandidateEdge(
                    source=e.source,
                    target=e.target,
                    interaction=e.interaction,
                    confidence=e.confidence,
                )
            )
            edges.add(key)

    return ExtractResponse(nodes=list(nodes.values()), edges=merged_edges, matched_patterns=rule.patterns)


async def run_hybrid_extract(text: str) -> HybridExtractResponse:
    """Hybrid = rule + optional LLM, with strict JSON validation."""
    rule = extract_rule_based(text)
    rule_resp = to_extract_response(rule)
    llm_payload: LLMExtractPayload | None = None
    try:
        llm_payload = await extract_llm(text)
    except Exception:
        llm_payload = None

    merged = merge_rule_and_llm(rule, llm_payload)
    prov_type = "rule" if llm_payload is None else "hybrid"
    llm_model = settings.llm_model_name if (llm_payload is not None) else None
    provenance: dict[str, str] = {
        "extractor_type": prov_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if llm_model:
        provenance["llm_model"] = llm_model
    provenance["llm_provider"] = settings.llm_provider or "none"
    return HybridExtractResponse(rule=rule_resp, llm=llm_payload, merged=merged, provenance=provenance)

