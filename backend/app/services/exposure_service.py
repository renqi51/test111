"""Candidate exposure surface generation from graph context + MCC/MNC.

This mid-stage version is graph-driven: it reads from the active graph backend
(Neo4j by default, file fallback) and derives naming patterns, protocols,
network functions, evidence docs and related risk hypotheses from relations.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.providers.llm_provider import get_llm_provider
from app.repositories.graph_repository import get_graph_repository
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
from app.services.prompt_registry_service import prompt_registry


def _pad_mnc(mnc: str) -> str:
    m = mnc.strip()
    if len(m) == 2:
        return f"0{m}"
    return m


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

    def fqdn_for_pattern(pattern_id: str) -> str | None:
        if pattern_id == "fqdn_ims":
            return f"ims.mnc{mnc3}.mcc{mcc}.pub.3gppnetwork.org"
        if pattern_id == "fqdn_wlan":
            return f"wlan.mnc{mnc3}.mcc{mcc}.3gppnetwork.org"
        if pattern_id == "fqdn_epdg":
            return f"epdg.epc.mnc{mnc3}.mcc{mcc}.pub.3gppnetwork.org"
        if pattern_id == "fqdn_n3iwf":
            return f"n3iwf.5gc.mnc{mnc3}.mcc{mcc}.pub.3gppnetwork.org"
        return None

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
        fqdn = fqdn_for_pattern(pid)
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

    # Fallback for Open Gateway demo: there is no FQDNPattern seed edge in v1,
    # but we still want an illustrative northbound endpoint candidate.
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
        fqdn = f"api.operator.mnc{mnc3}.mcc{mcc}.example"
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


def _deterministic_assessment(candidate: ExposureCandidate) -> ExposureAssessment:
    score = 0.2 + 0.3 * min(1.0, candidate.confidence)
    notes: list[str] = []
    if any("ipsec" in p.lower() or "ikev2" in p.lower() for p in candidate.protocols):
        score += 0.1
        notes.append("涉及隧道/鉴权协议，需关注边界暴露配置。")
    if any("https" in p.lower() or "rest" in p.lower() for p in candidate.protocols):
        score += 0.1
        notes.append("存在 northbound/web 暴露特征，建议校验鉴权与ACL。")
    if candidate.probe_status.get("permitted"):
        score += 0.08
    if candidate.probe_status.get("dns_ok"):
        score += 0.12
    if candidate.probe_status.get("https_ok") is True:
        score += 0.16
        notes.append("授权探测可达，属于真实可触达候选面。")
    if candidate.evidence.related_risks:
        score += min(0.14, 0.04 * len(candidate.evidence.related_risks))

    score = max(0.0, min(1.0, score))
    if score >= 0.8:
        level = "high"
    elif score >= 0.6:
        level = "medium"
    else:
        level = "low"
    return ExposureAssessment(
        candidate_id=candidate.candidate_id,
        risk_level=level,
        score=round(score, 4),
        summary=f"{candidate.candidate_fqdn} 的潜在暴露面等级为 {level}。",
        conservative_explanation="基于标准模式、图谱上下文与授权探测结果的保守评估。",
        attack_surface_notes=notes,
        missing_evidence=[] if candidate.evidence.evidence_docs else ["缺少标准条文证据映射"],
        evidence_refs=list(candidate.evidence.evidence_docs),
        model_name="deterministic",
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
    return ExposureAssessment(
        candidate_id=fallback.candidate_id,
        risk_level=level,  # type: ignore[arg-type]
        score=max(0.0, min(1.0, round(score, 4))),
        summary=str(raw.get("summary") or fallback.summary),
        conservative_explanation=str(raw.get("conservative_explanation") or fallback.conservative_explanation),
        attack_surface_notes=[str(x) for x in (raw.get("attack_surface_notes") or fallback.attack_surface_notes)],
        missing_evidence=[str(x) for x in (raw.get("missing_evidence") or fallback.missing_evidence)],
        evidence_refs=[str(x) for x in (raw.get("evidence_refs") or fallback.evidence_refs)],
        model_name=str(raw.get("model_name") or "llm"),
        fallback_used=False,
    )


async def _assess_candidate_with_llm(candidate: ExposureCandidate, fallback: ExposureAssessment) -> ExposureAssessment:
    if not (settings.llm_provider and settings.llm_base_url):
        return fallback
    prompt = prompt_registry.get("exposure_assessment")
    user_prompt = (
        "Candidate payload:\n"
        f"{candidate.model_dump_json(ensure_ascii=False)}\n\n"
        "Return JSON only."
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
        return _sanitize_assessment(raw, fallback)
    except Exception:  # noqa: BLE001
        fallback.fallback_used = True
        return fallback


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
        "## Candidate Assessments",
    ]
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
                "",
            ]
        )
    lines.append("## Attack Paths")
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
                    "",
                ]
            )
    lines.extend(
        [
            "## Safety Notice",
            "Probe is restricted to authorized lab environments only.",
            "This system does not include unauthorized scanning.",
        ]
    )
    return "\n".join(lines)


def _build_attack_paths(
    service: str,
    candidates: list[ExposureCandidate],
    assessments: list[ExposureAssessment],
) -> list[AttackPath]:
    by_id = {a.candidate_id: a for a in assessments}
    out: list[AttackPath] = []
    for idx, c in enumerate(candidates):
        a = by_id.get(c.candidate_id)
        if not a:
            continue
        pivots = []
        if c.probe_status.get("service_hints"):
            pivots.extend([f"fingerprint:{x}" for x in c.probe_status.get("service_hints", [])[:3]])
        pivots.extend([f"nf:{nf}" for nf in c.network_functions[:2]])
        likelihood = min(1.0, 0.35 + 0.45 * a.score + (0.1 if c.probe_status.get("https_ok") else 0.0))
        status = "partially_validated" if c.probe_status.get("dns_ok") or c.probe_status.get("open_ports") else "hypothesis"
        if c.probe_status.get("https_ok") is True:
            status = "validated"
        impact = "low"
        if any("gtp" in s.lower() for s in c.probe_status.get("service_hints", [])):
            impact = "high"
        elif a.risk_level in {"high", "critical"}:
            impact = "medium"
        out.append(
            AttackPath(
                path_id=f"path_{service.lower().replace(' ', '_')}_{idx:02d}",
                candidate_id=c.candidate_id,
                entrypoint=c.candidate_fqdn,
                pivots=list(dict.fromkeys(pivots)),
                target_asset=c.network_functions[0] if c.network_functions else service,
                likelihood=round(likelihood, 4),
                impact=impact,  # type: ignore[arg-type]
                prerequisites=[
                    "authorized laboratory scope",
                    "target in probe allowlist/open policy",
                ],
                evidence_refs=list(dict.fromkeys(c.evidence.evidence_docs + a.evidence_refs)),
                validation_status=status,  # type: ignore[arg-type]
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

    deterministic = [_deterministic_assessment(c) for c in candidates]
    assessments: list[ExposureAssessment]
    if use_llm:
        assessments = await asyncio.gather(
            *[_assess_candidate_with_llm(c, deterministic[idx]) for idx, c in enumerate(candidates)]
        )
    else:
        assessments = deterministic
    attack_paths = _build_attack_paths(service=service, candidates=candidates, assessments=assessments)

    summary = {
        "total_candidates": len(candidates),
        "high_or_critical": sum(1 for a in assessments if a.risk_level in {"high", "critical"}),
        "probe_reachable": sum(1 for c in candidates if c.probe_status.get("https_ok") is True),
        "attack_paths": len(attack_paths),
        "validated_paths": sum(1 for p in attack_paths if p.validation_status == "validated"),
        "llm_used": bool(use_llm and settings.llm_provider and settings.llm_base_url),
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
