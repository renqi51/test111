from fastapi import APIRouter

from app.schemas.extract import (
    ExtractRequest,
    ExtractResponse,
    HybridExtractResponse,
    LLMExtractPayload,
)
from app.services.extract_service import extract_llm, extract_rule_based, run_hybrid_extract

router = APIRouter(tags=["extract"])

SAMPLE_TEXTS = [
    {
        "id": "ims_sip",
        "title": "IMS 与 SIP、命名",
        "text": (
            "在运营商 IMS 部署中，终端与 P-CSCF 之间通常使用 SIP 建立会话；"
            "核心网侧还会涉及 I-CSCF 与 S-CSCF 的协作。"
            "与接入相关的 FQDN 常遵循类似 ims.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org 的模式，"
            "具体命名与编码规则在 3GPP TS 23.003 中有系统性说明，"
            "IMS 总体架构可参考 3GPP TS 23.228，SIP 细节见 3GPP TS 24.229。"
        ),
    },
    {
        "id": "n3iwf_epdg",
        "title": "非 3GPP 接入与解析",
        "text": (
            "当终端通过不可信 Wi-Fi 接入时，常经由 ePDG 建立到运营商的安全通道，"
            "协议侧多与 IKEv2、IPsec 以及 DNS 解析相关联。"
            "在 5G 场景下，N3IWF 承担非 3GPP 接入与 5GC 的互通，"
            "其服务实例命名可能出现 n3iwf.5gc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org 这类形态。"
            "相关流程与接口在 3GPP TS 24.502 等规范中描述。"
        ),
    },
    {
        "id": "open_gateway",
        "title": "Open Gateway 与 CAMARA",
        "text": (
            "GSMA Open Gateway 倡议强调以统一方式开放运营商网络能力；"
            "北向能力接口常以 HTTPS 与 REST 风格对外暴露。"
            "业界多在 CAMARA 项目中推进 API 共性（如 CAMARA Commonalities），"
            "身份与同意管理（Identity & Consent Management）也是能力开放中的关键组件。"
            "公开材料与 GSMA Open Gateway、CAMARA 文档站点可用于对照 API 结构与治理要求。"
        ),
    },
]


@router.post("/extract", response_model=ExtractResponse)
def extract_rule(body: ExtractRequest):
    """纯规则抽取，保持原行为。"""
    r = extract_rule_based(body.text)
    return ExtractResponse(nodes=r.nodes, edges=r.edges, matched_patterns=r.patterns)


@router.post("/extract/hybrid", response_model=HybridExtractResponse)
async def extract_hybrid(body: ExtractRequest):
    """规则 + LLM 混合抽取，LLM 失败则自动退化为纯规则。"""
    return await run_hybrid_extract(body.text)


@router.post("/extract/llm", response_model=LLMExtractPayload)
async def extract_llm_only(body: ExtractRequest):
    """仅调用 LLM 抽取（严格 JSON 校验）；LLM 未配置时返回空结构。"""
    try:
        payload = await extract_llm(body.text)
    except Exception as exc:  # noqa: BLE001
        return LLMExtractPayload(
            nodes=[],
            edges=[],
            risk_hypotheses=[],
            notes=[f"llm request failed: {str(exc)[:180]}"],
        )
    # 当 LLM 未配置/失败时，extract_llm 返回 None，这里返回空结构
    if payload is None:
        return LLMExtractPayload(nodes=[], edges=[], risk_hypotheses=[], notes=["llm disabled or failed"])
    return payload


@router.get("/extract/samples")
def extract_samples():
    return {"samples": SAMPLE_TEXTS}
