"""Outside-in exposure analysis: real assets → authorized live probe → candidates.

Candidates are grounded in `probe_service` observations (TCP/UDP banners and
service hints). MCC/MNC are optional report labels only; no graph-derived FQDN
guessing is performed in this module.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.schemas.extraction_pipeline import EvidencePack
from app.schemas.exposure import (
    AttackPath,
    CandidateEvidenceBundle,
    ExposureAnalysisResponse,
    ExposureAssessment,
    ExposureCandidate,
    ExposurePattern,
)
from app.schemas.probe import ProbeRunRequest
from app.services import probe_service
from app.services.graph_rag_query_service import get_graph_rag_query_service
from app.services.prompt_registry_service import prompt_registry
from app.services.spec_context_service import spec_context_service

_EVIDENCE_TEXT_CAP = 4000


def _normalize_asset_token(raw: str) -> str:
    s = raw.strip()
    if not s:
        return ""
    if "://" in s:
        from urllib.parse import urlparse

        parsed = urlparse(s)
        h = parsed.hostname
        return (h or "").lower()
    return s.split("/")[0].split(":")[0].lower().strip(".")


def expand_real_asset_targets(
    *,
    domains: Sequence[str],
    ips: Sequence[str],
    cidrs: Sequence[str],
    extra_hosts: Sequence[str] | None = None,
    max_cidr_hosts: int | None = None,
) -> list[str]:
    """Materialize host/IP strings for probing; order-stable and deduplicated."""
    cap = max_cidr_hosts if max_cidr_hosts is not None else settings.exposure_max_cidr_expand_hosts
    out: list[str] = []
    seen: set[str] = set()

    def push(h: str) -> None:
        n = _normalize_asset_token(h)
        if not n or n in seen:
            return
        seen.add(n)
        out.append(n)

    for d in domains:
        push(str(d))
    if extra_hosts:
        for d in extra_hosts:
            push(str(d))
    for ip in ips:
        push(str(ip))

    used = 0
    for c in cidrs:
        c = str(c).strip()
        if not c:
            continue
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.prefixlen == net.max_prefixlen:
            host_iter = [net.network_address]
        else:
            host_iter = list(net.hosts())
        for host in host_iter:
            if used >= cap:
                break
            push(str(host))
            used += 1
        if used >= cap:
            break

    return out


def _protocol_labels_from_probe_row(row: dict[str, Any]) -> list[str]:
    hints = [str(x) for x in (row.get("service_hints") or []) if x is not None]
    for p in row.get("open_ports") or []:
        try:
            hints.append(f"tcp/{int(p)}")
        except (TypeError, ValueError):
            continue
    for p in row.get("open_udp_ports") or []:
        try:
            hints.append(f"udp/{int(p)}")
        except (TypeError, ValueError):
            continue
    for line in row.get("udp_spike_findings") or []:
        s = str(line)
        if ":REPLY " in s:
            parts = s.split(":")
            if len(parts) >= 4:
                hints.append(f"spike_hit:{parts[1]}:{parts[2]}")
    for pkey in (row.get("tcp_banners") or {}).keys():
        hints.append(f"tcp_banner/{pkey}")
    dedup: list[str] = []
    sseen: set[str] = set()
    for h in hints:
        if h not in sseen:
            sseen.add(h)
            dedup.append(h)
    return dedup


def _risk_hypotheses_from_probe_row(row: dict[str, Any]) -> list[str]:
    if row.get("permitted") is False:
        reason = str(row.get("policy_reason") or "policy_denied")
        return [
            f"策略未放行（{reason}）：资产未进入主动包级探测链；在授权实验网调整 EXPOSURE_PROBE_MODE / "
            "suffix allowlist 或 probe_allowlist_cidrs 后复扫以获取端口与协议事实。"
        ]
    labels = " ".join(_protocol_labels_from_probe_row(row)).lower()
    out: list[str] = []
    if "https" in labels or "tcp/443" in labels:
        out.append(
            "HTTPS(443) 暴露：验证 ALPN/http2 与 TLS1.2/1.3 降级、Host 走私与反代路径规范化；"
            "对北向 OAuth2/OIDC 做 redirect_uri 绑定矩阵与 scope 提升尝试。"
        )
    if "sip" in labels or "tcp/5060" in labels:
        out.append(
            "SIP(5060) 响应：抓 REGISTER/INVITE 质询链，测异常方法/畸形 `Via`/`Route` 注入容忍度与 digest 中继边界。"
        )
    if "udp/500" in labels or "udp/4500" in labels or "ipsec" in labels:
        out.append(
            "IKE/IPsec(UDP 500/4500) 有回包：用畸形 IKE_SA_INIT（错误 major/minor、临界载荷）映射 NOTIFY 指纹与实现族。"
        )
    if "udp/2152" in labels or "gtp-u" in labels:
        out.append(
            "GTP-U(2152) 响应：枚举 TEID 可预测性与 echo 滥用面，测异常 GTP 头长度/类型组合下的静默丢弃 vs 错误码。"
        )
    if row.get("https_ok") is True:
        out.append(
            f"TLS+HTTP 栈存活（status={row.get('https_status')}）：拉取证书主体与链，比对 CT 遗漏子域与证书 SAN 过宽面。"
        )
    if not out and row.get("dns_ok") is True:
        out.append(
            "DNS 可达但未见配置端口命中：按授权范围扩大 TCP/UDP 端口表与 TLS ClientHello 指纹探测，排除仅对白名单源开放的静默丢弃。"
        )
    if row.get("dns_ok") is False and row.get("permitted") is True:
        err = row.get("error") or "dns_failure"
        out.append(f"解析失败（{err}）：核对爬虫根域、split-horizon 与内部 DNS 视图一致性。")
    if not out:
        out.append("无即时协议指纹：仍保留主机级事实入链，后续以全端口与被动监听补全。")
    return out


def _confidence_from_probe_row(row: dict[str, Any]) -> float:
    if row.get("permitted") is False:
        return 0.0
    tcp_n = len(row.get("open_ports") or [])
    udp_n = len(row.get("open_udp_ports") or [])
    base = 0.38 + 0.06 * (tcp_n + udp_n)
    if row.get("https_ok") is True:
        base += 0.12
    if row.get("dns_ok") is True:
        base += 0.05
    return round(min(0.95, base), 3)


def rows_from_probe_run(probe_run: dict[str, Any], *, service: str) -> list[dict[str, Any]]:
    """Build exposure table rows strictly from a serialized ProbeRunResponse."""
    _ = service
    rows: list[dict[str, Any]] = []
    for item in probe_run.get("results") or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or item.get("target") or "").strip()
        if not host:
            continue
        labels = _protocol_labels_from_probe_row(item)
        rows.append(
            {
                "candidate_fqdn": host,
                "protocol_stack": labels,
                "network_functions": [],
                "evidence_docs": [],
                "risk_hypotheses": _risk_hypotheses_from_probe_row(item),
                "confidence": _confidence_from_probe_row(item),
            }
        )
    for r in rows:
        r["protocol_stack"] = r.get("protocol_stack", [])
        r["network_functions"] = r.get("network_functions", [])
        r["risk_hypotheses"] = r.get("risk_hypotheses", [])
    return rows


async def generate_probe_backed_rows(
    *,
    service: str,
    domains: Sequence[str],
    ips: Sequence[str],
    cidrs: Sequence[str],
    extra_hosts: Sequence[str] | None,
    include_probe: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    targets = expand_real_asset_targets(
        domains=domains,
        ips=ips,
        cidrs=cidrs,
        extra_hosts=extra_hosts,
    )
    if not targets:
        raise ValueError("no_probe_targets_after_asset_expansion")
    if not include_probe:
        rows = [
            {
                "candidate_fqdn": h,
                "protocol_stack": [],
                "network_functions": [],
                "evidence_docs": [],
                "risk_hypotheses": [
                    "include_probe=false：未执行主动发包探测；无存活端口/协议事实，不应进入武器化阶段。"
                ],
                "confidence": 0.04,
            }
            for h in targets
        ]
        return rows, None
    probe_run = await probe_service.run_probe(
        ProbeRunRequest(targets=targets, context=f"exposure_outside_in:{service}")
    )
    dumped = probe_run.model_dump()
    return rows_from_probe_run(dumped, service=service), dumped


def _sanitize_str_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        s = raw.strip()
        return [s] if s else []
    if isinstance(raw, list):
        out: list[str] = []
        for x in raw:
            if x is None:
                continue
            s = str(x).strip()
            if s:
                out.append(s)
        return out
    return []


def _serialize_retrieved_evidence(evidence_pack: EvidencePack) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for it in evidence_pack.items:
        text = it.text or ""
        if len(text) > _EVIDENCE_TEXT_CAP:
            text = text[:_EVIDENCE_TEXT_CAP] + "…"
        out.append(
            {
                "evidence_id": it.evidence_id,
                "document_id": it.document_id,
                "heading": it.heading,
                "relevance_score": it.relevance_score,
                "text": text,
            }
        )
    return out


def _build_exposure_prompt_payload(candidate: ExposureCandidate, evidence_pack: EvidencePack) -> str:
    probe = candidate.probe_status if isinstance(candidate.probe_status, dict) else {}
    cand_json = candidate.model_dump(mode="json")
    evidence = _serialize_retrieved_evidence(evidence_pack)
    return "\n".join(
        [
            "Candidate payload (JSON):",
            json.dumps(cand_json, ensure_ascii=False, indent=2),
            "",
            "Probe observations (JSON):",
            json.dumps(probe, ensure_ascii=False, indent=2),
            "",
            "Retrieved standard evidence (evidence_id, document_id, heading, text, relevance_score):",
            json.dumps(evidence, ensure_ascii=False, indent=2),
            "",
            "Return JSON only.",
        ]
    )


def _build_patterns(service: str, rows: list[dict[str, Any]]) -> list[ExposurePattern]:
    out: list[ExposurePattern] = []
    for idx, row in enumerate(rows):
        expr = row["candidate_fqdn"]
        try:
            ipaddress.ip_address(expr)
            cat = "route"
        except ValueError:
            cat = "fqdn"
        out.append(
            ExposurePattern(
                pattern_id=f"pat_{service.lower().replace(' ', '_')}_{idx:02d}",
                service=service,
                category=cat,
                expression=expr,
                rationale="Observed attack surface entrypoint from authorized active probe of supplied assets (outside-in).",
                evidence_docs=row.get("evidence_docs", []),
            )
        )
    return out


def _as_candidate(service: str, row: dict[str, Any], idx: int) -> ExposureCandidate:
    nfs = row.get("network_functions") or []
    graph_paths = [f"{service}->uses_network_function->{nf}" for nf in nfs[:4]]
    if not graph_paths:
        graph_paths = [f"outside_in:live_probe->{row['candidate_fqdn']}"]
    return ExposureCandidate(
        candidate_id=f"cand_{idx:03d}",
        candidate_fqdn=row["candidate_fqdn"],
        service=service,
        protocols=row.get("protocol_stack", []),
        network_functions=nfs,
        confidence=float(row.get("confidence", 0.0)),
        evidence=CandidateEvidenceBundle(
            evidence_docs=row.get("evidence_docs", []),
            graph_paths=graph_paths,
            related_risks=row.get("risk_hypotheses", []),
            source_kind=["probe_observation"],
        ),
        probe_status={},
    )


async def _graph_rag_assessment_for_candidate(candidate: ExposureCandidate) -> ExposureAssessment:
    """无硬编码权重：完全依赖 GraphRAG+LLM 的结构化输出。"""
    if not settings.llm_enabled:
        return ExposureAssessment(
            candidate_id=candidate.candidate_id,
            risk_level="low",
            score=0.0,
            summary="LLM/GraphRAG 未配置，无法生成基于图谱的评估。",
            conservative_explanation="请在授权环境中配置 LLM 与 GraphRAG 后再运行分析。",
            missing_evidence=["llm_disabled"],
            evidence_refs=list(candidate.evidence.evidence_docs),
            model_name="disabled",
            fallback_used=True,
        )
    gr = get_graph_rag_query_service()
    syn = await gr.synthesize_exposure_assessment(
        service=candidate.service,
        candidate=candidate.model_dump(mode="json"),
    )
    return ExposureAssessment(
        candidate_id=candidate.candidate_id,
        risk_level=syn.risk_level,
        score=round(float(syn.score), 4),
        summary=syn.summary or f"{candidate.candidate_fqdn} 图谱驱动评估。",
        conservative_explanation=syn.conservative_explanation or "基于 GraphRAG 证据上下文的保守结论。",
        attack_surface_notes=list(syn.attack_surface_notes),
        attack_points=list(syn.attack_points),
        validation_tasks=list(syn.validation_tasks),
        missing_evidence=list(syn.missing_evidence),
        evidence_refs=list(dict.fromkeys([*candidate.evidence.evidence_docs, *syn.evidence_refs])),
        model_name="graph_rag_synthesis",
        fallback_used=False,
    )


def _sanitize_assessment(raw: dict[str, Any], fallback: ExposureAssessment) -> ExposureAssessment:
    level = str(raw.get("risk_level") or fallback.risk_level).lower()
    if level not in {"low", "medium", "high", "critical"}:
        level = fallback.risk_level
    try:
        score = float(raw.get("score", fallback.score))
    except Exception:  # noqa: BLE001
        score = fallback.score
    ap_raw = raw.get("attack_points")
    vt_raw = raw.get("validation_tasks")
    attack_points = _sanitize_str_list(ap_raw) if ap_raw is not None else list(fallback.attack_points)
    validation_tasks = _sanitize_str_list(vt_raw) if vt_raw is not None else list(fallback.validation_tasks)
    return ExposureAssessment(
        candidate_id=fallback.candidate_id,
        risk_level=level,  # type: ignore[arg-type]
        score=max(0.0, min(1.0, round(score, 4))),
        summary=str(raw.get("summary") or fallback.summary),
        conservative_explanation=str(raw.get("conservative_explanation") or fallback.conservative_explanation),
        attack_surface_notes=[str(x) for x in (raw.get("attack_surface_notes") or fallback.attack_surface_notes)],
        attack_points=attack_points,
        validation_tasks=validation_tasks,
        missing_evidence=[str(x) for x in (raw.get("missing_evidence") or fallback.missing_evidence)],
        evidence_refs=[str(x) for x in (raw.get("evidence_refs") or fallback.evidence_refs)],
        model_name=str(raw.get("model_name") or "llm"),
        fallback_used=False,
    )


async def _assess_candidate_with_llm(candidate: ExposureCandidate) -> ExposureAssessment:
    if not settings.llm_enabled:
        return await _graph_rag_assessment_for_candidate(candidate)
    prompt = prompt_registry.get("exposure_assessment")
    try:
        evidence_pack = spec_context_service.retrieve_for_candidate(
            service=candidate.service,
            network_functions=candidate.network_functions,
            protocols=candidate.protocols,
            related_risks=candidate.evidence.related_risks,
            top_k=settings.exposure_evidence_top_k,
        )
    except Exception:  # noqa: BLE001
        evidence_pack = EvidencePack(
            pack_id="pack_err",
            query="",
            document_id="",
            scenario_hint="exposure_spec",
            items=[],
            retrieval_strategy="error",
        )
    user_prompt = _build_exposure_prompt_payload(candidate, evidence_pack)
    sanitize_baseline = ExposureAssessment(
        candidate_id=candidate.candidate_id,
        risk_level="low",
        score=0.0,
        summary="",
        evidence_refs=list(candidate.evidence.evidence_docs),
        model_name="sanitize_baseline",
    )
    try:
        llm = await get_llm_provider().chat_json(
            system_prompt=prompt.template,
            user_prompt=user_prompt,
            model_name=settings.extraction_judge_model,
            temperature=0.1,
        )
        raw = llm.raw if isinstance(llm.raw, dict) else {}
        raw["model_name"] = llm.model
        return _sanitize_assessment(raw, sanitize_baseline)
    except Exception:  # noqa: BLE001
        return (await _graph_rag_assessment_for_candidate(candidate)).model_copy(update={"fallback_used": True})


def _report_markdown(data: ExposureAnalysisResponse) -> str:
    lines = [
        f"# Exposure Analysis Report: {data.run_id}",
        "",
        f"- Service: {data.service}",
        f"- MCC/MNC: {data.mcc}/{data.mnc}",
        f"- Candidates: {len(data.candidates)}",
        f"- Assessments: {len(data.assessments)}",
        f"- Probe integrated: {'yes' if data.probe_run else 'no'}",
        "",
        "## 针对该资产的建议测试操作（汇总）",
    ]
    concrete: list[str] = []
    for p in data.attack_paths:
        for i, step in enumerate(p.techniques, start=1):
            concrete.append(f"{p.entrypoint} / {p.path_id}: {i}. {step}")
    for a in data.assessments:
        for i, task in enumerate(a.validation_tasks, start=1):
            concrete.append(f"{a.candidate_id} 验证任务: {i}. {task}")
        for i, ap in enumerate(a.attack_points, start=1):
            concrete.append(f"{a.candidate_id} 攻击点假设: {i}. {ap}")
    if concrete:
        lines.extend(f"- {x}" for x in concrete[:80])
    else:
        lines.append("- （当前运行未产生结构化测试步骤；请检查 GraphRAG/LLM 配置与图谱威胁链。）")
    lines.extend(
        [
            "",
            "## Candidate Assessments",
        ]
    )
    by_id = {a.candidate_id: a for a in data.assessments}
    for c in data.candidates:
        a = by_id.get(c.candidate_id)
        lines.extend(
            [
                f"### {c.candidate_fqdn}",
                f"- Level/Score: {a.risk_level if a else 'unknown'} / {a.score if a else 0}",
                f"- Protocols: {', '.join(c.protocols) or 'n/a'}",
                f"- Network Functions: {', '.join(c.network_functions) or 'n/a'}",
                f"- Evidence docs: {', '.join(c.evidence.evidence_docs) or 'n/a'}",
                f"- Probe: DNS={c.probe_status.get('dns_ok')} HTTPS={c.probe_status.get('https_ok')} status={c.probe_status.get('https_status')}",
                f"- Summary: {a.summary if a else ''}",
                f"- Attack points: {', '.join(a.attack_points) if a and a.attack_points else '—'}",
                f"- Validation tasks: {', '.join(a.validation_tasks) if a and a.validation_tasks else '—'}",
                "",
            ]
        )
    lines.append("## Attack Paths (GraphRAG 驱动)")
    if not data.attack_paths:
        lines.append("- no attack path generated")
    else:
        for p in data.attack_paths:
            lines.extend(
                [
                    f"### {p.path_id}",
                    f"- Entrypoint: {p.entrypoint}",
                    f"- Pivots: {', '.join(p.pivots) if p.pivots else 'n/a'}",
                    f"- Target: {p.target_asset}",
                    f"- Likelihood: {p.likelihood}",
                    f"- Impact: {p.impact}",
                    f"- Validation: {p.validation_status}",
                    f"- Threat vectors: {', '.join(p.threat_vectors) if p.threat_vectors else '—'}",
                    f"- Vulnerabilities (context): {', '.join(p.vulnerabilities) if p.vulnerabilities else '—'}",
                    f"- GraphRAG confidence: {p.graph_rag_confidence}",
                ]
            )
            if p.techniques:
                lines.append("- 建议测试操作:")
                lines.extend(f"  {i}. {t}" for i, t in enumerate(p.techniques, start=1))
            lines.append("")
    lines.extend(
        [
            "## Safety Notice",
            "Probe is restricted to authorized lab environments only.",
            "This system does not include unauthorized scanning.",
        ]
    )
    return "\n".join(lines)


async def _build_attack_paths_via_graph_rag(
    service: str,
    candidates: list[ExposureCandidate],
    assessments: list[ExposureAssessment],
) -> list[AttackPath]:
    """通过 GraphRAG 问答管线拉取子图并由 LLM 结构化填充 AttackPath（禁止本地 impact 推断）。"""
    by_id = {a.candidate_id: a for a in assessments}
    gr = get_graph_rag_query_service()
    out: list[AttackPath] = []
    for idx, c in enumerate(candidates):
        a = by_id.get(c.candidate_id)
        if not a:
            continue
        cand_dump = c.model_dump(mode="json")
        batch = await gr.synthesize_exposure_attack_path(
            service=service,
            candidate=cand_dump,
            assessment=a.model_dump(mode="json"),
        )
        row = batch.paths[0] if batch.paths else None
        pivots = list(row.pivots) if row else []
        if c.probe_status.get("service_hints"):
            pivots = list(
                dict.fromkeys(
                    [*pivots, *[f"probe_hint:{x}" for x in c.probe_status.get("service_hints", [])[:5]]],
                )
            )
        techniques = list(row.techniques) if row else []
        tvs = list(row.threat_vectors) if row else []
        vulns = list(row.vulnerabilities) if row else []
        refs = list(row.evidence_refs) if row else []
        out.append(
            AttackPath(
                path_id=f"path_{service.lower().replace(' ', '_')}_{idx:02d}",
                candidate_id=c.candidate_id,
                entrypoint=c.candidate_fqdn,
                pivots=pivots,
                target_asset=(row.target_asset if row and row.target_asset else (c.network_functions[0] if c.network_functions else service)),
                likelihood=round(float(row.likelihood), 4) if row else 0.0,
                impact=(row.impact if row else "medium"),  # type: ignore[arg-type]
                prerequisites=list(row.prerequisites) if row else ["authorized laboratory scope"],
                evidence_refs=list(dict.fromkeys([*c.evidence.evidence_docs, *a.evidence_refs, *refs])),
                validation_status=(row.validation_status if row else "hypothesis"),  # type: ignore[arg-type]
                techniques=techniques,
                threat_vectors=tvs,
                vulnerabilities=vulns,
                graph_rag_confidence=round(float(row.confidence), 4) if row else 0.0,
                graph_rag_analyst_notes=list(batch.analyst_notes),
            )
        )
    return out


async def analyze_exposure(
    service: str,
    mcc: str,
    mnc: str,
    *,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
    cidrs: list[str] | None = None,
    include_probe: bool = True,
    extra_hosts: list[str] | None = None,
    use_llm: bool = True,
) -> ExposureAnalysisResponse:
    run_id = f"exp_{uuid4().hex[:10]}"
    probe_run_payload: dict | None = None
    rows: list[dict[str, Any]] = []
    try:
        rows, probe_run_payload = await generate_probe_backed_rows(
            service=service,
            domains=domains or [],
            ips=ips or [],
            cidrs=cidrs or [],
            extra_hosts=extra_hosts,
            include_probe=include_probe,
        )
    except (RuntimeError, ValueError) as exc:
        probe_run_payload = {"error": str(exc), "results": []}
        tlist = expand_real_asset_targets(
            domains=domains or [],
            ips=ips or [],
            cidrs=cidrs or [],
            extra_hosts=extra_hosts,
        )
        if tlist:
            rows = [
                {
                    "candidate_fqdn": h,
                    "protocol_stack": [],
                    "network_functions": [],
                    "evidence_docs": [],
                    "risk_hypotheses": [
                        f"主动探测链中断（{exc!s}）：在授权靶场启用并放行 probe 后重跑以填充存活端口/协议事实。"
                    ],
                    "confidence": 0.0,
                }
                for h in tlist
            ]
    except Exception as exc:  # noqa: BLE001
        probe_run_payload = {"error": f"probe_failed:{exc}", "results": []}

    if not rows and probe_run_payload and isinstance(probe_run_payload.get("results"), list):
        rows = rows_from_probe_run(probe_run_payload, service=service)

    patterns = _build_patterns(service, rows)
    candidates = [_as_candidate(service, row, idx) for idx, row in enumerate(rows)]

    probe_map: dict[str, Any] = {}
    if probe_run_payload and isinstance(probe_run_payload.get("results"), list):
        probe_map = {str(item.get("host")): item for item in probe_run_payload["results"] if isinstance(item, dict)}
    for c in candidates:
        c.probe_status = dict(probe_map.get(c.candidate_fqdn, {}))
        if c.probe_status:
            if "probe_observation" not in c.evidence.source_kind:
                c.evidence.source_kind.append("probe_observation")

    assessments: list[ExposureAssessment]
    if use_llm:
        assessments = await asyncio.gather(*[_assess_candidate_with_llm(c) for c in candidates])
    else:
        assessments = await asyncio.gather(*[_graph_rag_assessment_for_candidate(c) for c in candidates])
    attack_paths = await _build_attack_paths_via_graph_rag(service=service, candidates=candidates, assessments=assessments)

    summary = {
        "total_candidates": len(candidates),
        "high_or_critical": sum(1 for a in assessments if a.risk_level in {"high", "critical"}),
        "probe_reachable": sum(1 for c in candidates if c.probe_status.get("https_ok") is True),
        "attack_paths": len(attack_paths),
        "validated_paths": sum(1 for p in attack_paths if p.validation_status == "validated"),
        "llm_used": bool(use_llm and settings.llm_enabled),
    }

    response = ExposureAnalysisResponse(
        run_id=run_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        service=service,
        mcc=mcc,
        mnc=mnc,
        patterns=patterns,
        candidates=candidates,
        assessments=assessments,
        attack_paths=attack_paths,
        probe_run=probe_run_payload,
        summary=summary,
    )

    runtime_root = Path(settings.extraction_runtime_path) / "exposure_runs"
    runtime_root.mkdir(parents=True, exist_ok=True)
    json_path = runtime_root / f"{run_id}.json"
    report_path = runtime_root / f"{run_id}.md"
    report_md = _report_markdown(response)
    report_path.write_text(report_md, encoding="utf-8")
    response.report_path = str(report_path)
    json_path.write_text(response.model_dump_json(indent=2, ensure_ascii=False), encoding="utf-8")
    return response


def load_exposure_analysis(run_id: str) -> ExposureAnalysisResponse | None:
    runtime_root = Path(settings.extraction_runtime_path) / "exposure_runs"
    payload_path = runtime_root / f"{run_id}.json"
    if not payload_path.exists():
        return None
    raw = json.loads(payload_path.read_text(encoding="utf-8"))
    return ExposureAnalysisResponse.model_validate(raw)
