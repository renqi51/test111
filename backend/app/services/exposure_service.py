"""Candidate exposure surface generation from graph context + MCC/MNC.

This mid-stage version is graph-driven: it reads from the active graph backend
(Neo4j by default, file fallback) and derives naming patterns, protocols,
network functions, evidence docs and related risk hypotheses from relations.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.repositories.graph_repository import get_graph_repository
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

# Fallback when the graph has no Open Gateway naming pattern (must stay parameterized).
DEFAULT_OPEN_GATEWAY_FQDN_TEMPLATE = "api.operator.mnc{mnc}.mcc{mcc}.example"

_EVIDENCE_TEXT_CAP = 4000


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


def _pad_mnc(mnc: str) -> str:
    m = mnc.strip()
    if len(m) == 2:
        return f"0{m}"
    return m


def _normalize_mcc(mcc: str) -> str:
    s = mcc.strip()
    if s.isdigit():
        return s.zfill(3)
    return s


def _looks_like_fqdn_template(s: str) -> bool:
    sl = s.lower()
    if "." not in s:
        return False
    return ("mnc" in sl or "MNC" in s) and ("mcc" in sl or "MCC" in s) and ("{" in s or "<" in s)


def fqdn_template_from_node(node: dict[str, Any]) -> str | None:
    for key in ("template", "expression"):
        v = node.get(key)
        if isinstance(v, str) and _looks_like_fqdn_template(v):
            return v.strip()
    for key in ("en_identifier", "description", "label"):
        v = node.get(key)
        if isinstance(v, str) and _looks_like_fqdn_template(v):
            return v.strip()
    return None


def render_fqdn_template(template: str, mcc: str, mnc3: str) -> str:
    mcc_n = _normalize_mcc(mcc)
    mnc_n = mnc3.strip()
    out = template
    out = re.sub(r"\{mcc\}", mcc_n, out, flags=re.IGNORECASE)
    out = re.sub(r"\{mnc\}", mnc_n, out, flags=re.IGNORECASE)
    out = re.sub(r"<MCC>", mcc_n, out, flags=re.IGNORECASE)
    out = re.sub(r"<MNC>", mnc_n, out, flags=re.IGNORECASE)
    return out


def generate_rows(service: str, mcc: str, mnc: str) -> list[dict[str, Any]]:
    mnc3 = _pad_mnc(mnc)
    graph = get_graph_repository().get_graph()
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])

    # Map UI service name -> canonical service node id in the graph.
    svc_key = service.strip().lower()
    svc_id: str | None = None
    if svc_key in ("ims",):
        svc_id = "svc_ims"
    elif svc_key in ("vowifi", "vo-wifi", "wifi"):
        svc_id = "svc_vowifi"
    elif svc_key in ("open gateway", "opengateway", "open_gateway"):
        svc_id = "svc_open_gateway"

    if not svc_id:
        # Unknown service: keep demo deterministic but safe.
        return [
            {
                "candidate_fqdn": f"svc.{svc_key}.mnc{mnc3}.mcc{mcc}.demo.local",
                "protocol_stack": ["HTTPS"],
                "network_functions": [],
                "evidence_docs": [],
                "risk_hypotheses": [],
                "confidence": 0.2,
            }
        ]

    # -------- helpers ------------------------------------------------------

    def labels_of(node_ids: list[str]) -> list[str]:
        out: list[str] = []
        for nid in node_ids:
            n = nodes.get(nid)
            if n and n.get("label"):
                out.append(n["label"])
        # stable unique
        seen = set()
        uniq: list[str] = []
        for x in out:
            if x in seen:
                continue
            seen.add(x)
            uniq.append(x)
        return uniq

    def rendered_fqdn_for_pattern(pattern_id: str) -> str | None:
        node = nodes.get(pattern_id)
        if not node:
            return None
        ntype = node.get("type")
        if ntype not in ("FQDNPattern", "NamingRule"):
            return None
        tmpl = fqdn_template_from_node(node)
        if not tmpl:
            return None
        return render_fqdn_template(tmpl, mcc, mnc3)

    def find_targets(source: str, interaction: str) -> list[str]:
        return [e["target"] for e in edges if e.get("source") == source and e.get("interaction") == interaction]

    # -------- derive context from graph ----------------------------------

    # 1) related network functions (direct uses_network_function)
    direct_nfs = find_targets(svc_id, "uses_network_function")
    # 2) naming pattern nodes reachable from service and its NFs
    direct_patterns = find_targets(svc_id, "uses_naming_pattern")
    nf_patterns: list[str] = []
    for nf in direct_nfs:
        nf_patterns.extend(find_targets(nf, "uses_naming_pattern"))
    pattern_ids = list(dict.fromkeys(direct_patterns + nf_patterns))

    # 3) protocol stack: service-level uses_protocol + NF-level uses_protocol/resolved_via
    svc_proto_ids = find_targets(svc_id, "uses_protocol")
    nf_proto_ids: list[str] = []
    for nf in direct_nfs:
        nf_proto_ids.extend(find_targets(nf, "uses_protocol"))
        nf_proto_ids.extend(find_targets(nf, "resolved_via"))
    proto_ids = list(dict.fromkeys(svc_proto_ids + nf_proto_ids))
    protocol_stack = labels_of([pid for pid in proto_ids if nodes.get(pid, {}).get("type") == "Protocol"])

    # 4) evidence docs: pattern --documented_in--> StandardDoc
    # 5) risk hypotheses: service / reachable NFs / reachable Interfaces --targets--> RiskHypothesis
    risk_ids: list[str] = []
    interfaces = find_targets(svc_id, "exposes_interface")
    for src in [svc_id] + direct_nfs + interfaces:
        risk_ids.extend(find_targets(src, "targets"))
    risk_ids = list(dict.fromkeys(risk_ids))

    risk_labels = labels_of([rid for rid in risk_ids if nodes.get(rid, {}).get("type") == "RiskHypothesis"])

    # -------- build candidate rows ----------------------------------------
    rows: list[dict[str, Any]] = []

    for pid in pattern_ids:
        fqdn = rendered_fqdn_for_pattern(pid)
        if not fqdn:
            continue

        # network functions relevant for this naming pattern
        pattern_nfs: list[str] = []
        # pattern linked from NFs
        for nf in direct_nfs:
            if any(
                e.get("source") == nf and e.get("target") == pid and e.get("interaction") == "uses_naming_pattern"
                for e in edges
            ):
                pattern_nfs.append(nf)
        # pattern linked directly from service (fallback)
        if not pattern_nfs and pid in direct_patterns:
            pattern_nfs = direct_nfs if direct_nfs else [svc_id]

        docs = labels_of(find_targets(pid, "documented_in"))
        # confidence: simple heuristic based on docs presence
        conf = 0.55 + min(0.3, 0.08 * len(docs))

        rows.append(
            {
                "candidate_fqdn": fqdn,
                "source_service": nodes.get(svc_id, {}).get("label", service),
                "related_protocols": protocol_stack,
                "related_network_functions": labels_of(pattern_nfs),
                "evidence_docs": docs,
                "related_risks": risk_labels,
                "confidence": round(conf, 3),
            }
        )

    # Open Gateway: graph-first northbound FQDN template; parameterized fallback if missing.
    if not rows and svc_id == "svc_open_gateway":
        platforms = find_targets(svc_id, "implemented_via")
        docs = labels_of(
            [
                did
                for p in platforms
                for did in find_targets(p, "documented_in")
                if nodes.get(did, {}).get("type") == "StandardDoc"
            ]
        )
        tmpl: str | None = None
        for src in [svc_id, *interfaces]:
            for pid in find_targets(src, "uses_naming_pattern"):
                n = nodes.get(pid)
                if n and n.get("type") in ("FQDNPattern", "NamingRule"):
                    tmpl = fqdn_template_from_node(n)
                    if tmpl:
                        break
            if tmpl:
                break
        if not tmpl:
            tmpl = DEFAULT_OPEN_GATEWAY_FQDN_TEMPLATE
        fqdn = render_fqdn_template(tmpl, mcc, mnc3)
        rows.append(
            {
                "candidate_fqdn": fqdn,
                "source_service": nodes.get(svc_id, {}).get("label", service),
                "related_protocols": protocol_stack,
                "related_network_functions": labels_of(interfaces),
                "evidence_docs": docs,
                "related_risks": risk_labels,
                "confidence": 0.6,
            }
        )

    # Backward compatible keys for existing UI
    # (ExposureView expects protocol_stack/network_functions/risk_hypotheses)
    for r in rows:
        r["protocol_stack"] = r.get("related_protocols", [])
        r["network_functions"] = r.get("related_network_functions", [])
        r["risk_hypotheses"] = r.get("related_risks", [])
        # remove internal aliases (keep both)
    return rows


def _build_patterns(service: str, rows: list[dict[str, Any]]) -> list[ExposurePattern]:
    out: list[ExposurePattern] = []
    for idx, row in enumerate(rows):
        out.append(
            ExposurePattern(
                pattern_id=f"pat_{service.lower().replace(' ', '_')}_{idx:02d}",
                service=service,
                category="fqdn",
                expression=row["candidate_fqdn"],
                rationale="Derived from 3GPP/GSMA naming pattern and graph relations.",
                evidence_docs=row.get("evidence_docs", []),
            )
        )
    return out


def _as_candidate(service: str, row: dict[str, Any], idx: int) -> ExposureCandidate:
    graph_paths = [
        f"{service}->uses_network_function->{nf}" for nf in (row.get("network_functions") or [])[:4]
    ]
    return ExposureCandidate(
        candidate_id=f"cand_{idx:03d}",
        candidate_fqdn=row["candidate_fqdn"],
        service=service,
        protocols=row.get("protocol_stack", []),
        network_functions=row.get("network_functions", []),
        confidence=float(row.get("confidence", 0.0)),
        evidence=CandidateEvidenceBundle(
            evidence_docs=row.get("evidence_docs", []),
            graph_paths=graph_paths,
            related_risks=row.get("risk_hypotheses", []),
            source_kind=["standard_pattern", "graph_inference"],
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
    include_probe: bool = True,
    extra_hosts: list[str] | None = None,
    use_llm: bool = True,
) -> ExposureAnalysisResponse:
    run_id = f"exp_{uuid4().hex[:10]}"
    rows = generate_rows(service=service, mcc=mcc, mnc=mnc)
    patterns = _build_patterns(service, rows)
    candidates = [_as_candidate(service, row, idx) for idx, row in enumerate(rows)]

    probe_run_payload: dict | None = None
    if include_probe:
        targets = [c.candidate_fqdn for c in candidates]
        if extra_hosts:
            targets.extend([h.strip() for h in extra_hosts if h.strip()])
        if targets:
            try:
                probe_run = await probe_service.run_probe(ProbeRunRequest(targets=targets, context=f"exposure:{service}"))
                probe_run_payload = probe_run.model_dump()
            except Exception:  # noqa: BLE001
                probe_run_payload = {"error": "probe unavailable or blocked by policy"}

    probe_map = {}
    if probe_run_payload and isinstance(probe_run_payload.get("results"), list):
        probe_map = {str(item.get("host")): item for item in probe_run_payload["results"] if isinstance(item, dict)}
    for c in candidates:
        c.probe_status = probe_map.get(c.candidate_fqdn, {})
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
