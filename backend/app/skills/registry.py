from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict

from app.schemas.extract import ExtractRequest, HybridExtractResponse
from app.schemas.graph import GraphPayload
from app.schemas.exposure import ExposureGenerateRequest, ExposureRow
from app.services import extract_service, graph_engine
from app.repositories.graph_repository import get_graph_repository
from app.services.exposure_service import generate_rows
from app.services.report_service import build_demo_summary_md, build_validation_markdown
from app.schemas.probe import ProbeRunRequest
from app.services import probe_service
from app.schemas.extraction_pipeline import ExtractionRunRequest
from app.services.llm_orchestrator_service import llm_orchestrator_service
from app.services.trace_service import trace_service
from app.services.merge_service import merge_service


@dataclass
class SkillMetadata:
    name: str
    display_name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    tags: list[str]


SkillCallable = Callable[[dict[str, Any]], Any]


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: Dict[str, tuple[SkillMetadata, SkillCallable]] = {}

    def register(self, meta: SkillMetadata, func: SkillCallable) -> None:
        self._skills[meta.name] = (meta, func)

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": m.name,
                "display_name": m.display_name,
                "description": m.description,
                "input_schema": m.input_schema,
                "output_schema": m.output_schema,
                "tags": m.tags,
            }
            for m, _ in self._skills.values()
        ]

    def get(self, name: str) -> tuple[SkillMetadata, SkillCallable] | None:
        return self._skills.get(name)


registry = SkillRegistry()


def _init_builtin_skills() -> None:
    async def _build_evidence_pack(args: dict[str, Any]) -> dict[str, Any]:
        req = ExtractionRunRequest(
            text=args.get("text", ""),
            scenario_hint=args.get("scenario_hint", "IMS"),
            budget_mode="default",
        )
        run = await llm_orchestrator_service.run(req)
        return {
            "run_id": run.run_id,
            "evidence_pack": run.evidence_pack.model_dump(),
            "stage": run.stage,
        }

    registry.register(
        SkillMetadata(
            name="build_evidence_pack",
            display_name="Build Evidence Pack",
            description="构造共享证据包并返回 run_id。",
            input_schema={"type": "object", "properties": {"text": {"type": "string"}, "scenario_hint": {"type": "string"}}, "required": ["text"]},
            output_schema={"type": "object", "properties": {"run_id": {}, "evidence_pack": {}, "stage": {}}},
            tags=["extraction", "evidence"],
        ),
        _build_evidence_pack,
    )

    # 1. extract_spec_knowledge
    async def _extract_spec_knowledge(args: dict[str, Any]) -> dict[str, Any]:
        text = args.get("text") or ""
        res = await extract_service.run_hybrid_extract(text)
        # Ensure JSON serializable output
        return res.model_dump()

    registry.register(
        SkillMetadata(
            name="extract_spec_knowledge",
            display_name="Extract Spec Knowledge",
            description="从标准/说明文本中抽取服务、网元、协议、命名规则、风险线索等（规则+LLM 混合）。",
            input_schema={"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
            output_schema={"type": "object", "properties": {"rule": {}, "llm": {}, "merged": {}, "provenance": {}}},
            tags=["extract", "llm", "graph"],
        ),
        _extract_spec_knowledge,
    )

    # 2. merge_graph_entities
    def _merge(args: dict[str, Any]) -> dict[str, Any]:
        repo = get_graph_repository()
        payload = repo.merge_nodes_edges(args.get("nodes", []), args.get("edges", []))
        return payload

    registry.register(
        SkillMetadata(
            name="merge_graph_entities",
            display_name="Merge Graph Entities",
            description="将候选节点和边合并写入当前图谱（去重）。",
            input_schema={"type": "object", "properties": {"nodes": {}, "edges": {}}, "required": []},
            output_schema={"type": "object", "properties": {"nodes": {}, "edges": {}}},
            tags=["graph", "mutating"],
        ),
        _merge,
    )

    # 3. query_graph_context
    def _query(args: dict[str, Any]) -> GraphPayload:
        node_id = args.get("node_id")
        depth = int(args.get("depth", 1))
        repo = get_graph_repository()
        sub = repo.neighbors(node_id, depth=depth)
        return GraphPayload(nodes=sub["nodes"], edges=sub["edges"])

    registry.register(
        SkillMetadata(
            name="query_graph_context",
            display_name="Query Graph Context",
            description="查询某个节点周围的邻居子图。",
            input_schema={"type": "object", "properties": {"node_id": {"type": "string"}, "depth": {"type": "integer"}}},
            output_schema={"type": "object", "properties": {"nodes": {}, "edges": {}}},
            tags=["graph", "query"],
        ),
        _query,
    )

    # 4. generate_exposure_candidates
    def _gen(args: dict[str, Any]) -> list[ExposureRow]:
        req = ExposureGenerateRequest(**args)
        rows = generate_rows(req.service, req.mcc, req.mnc)
        return [ExposureRow.model_validate(r) for r in rows]

    registry.register(
        SkillMetadata(
            name="generate_exposure_candidates",
            display_name="Generate Exposure Candidates",
            description="基于图谱和 MCC/MNC 生成候选暴露面条目。",
            input_schema={"type": "object", "properties": {"service": {}, "mcc": {}, "mnc": {}}, "required": ["service", "mcc", "mnc"]},
            output_schema={"type": "array", "items": {}},
            tags=["exposure", "graph"],
        ),
        _gen,
    )

    # 4b. run_authorized_probe
    async def _probe(args: dict[str, Any]) -> dict[str, Any]:
        targets = args.get("targets") or []
        if not isinstance(targets, list):
            targets = []
        ctx = args.get("context")
        req = ProbeRunRequest(targets=[str(t) for t in targets], context=str(ctx) if ctx else None)
        res = await probe_service.run_probe(req)
        return res.model_dump()

    registry.register(
        SkillMetadata(
            name="run_authorized_probe",
            display_name="Run Authorized Probe",
            description="在配置策略内对主机名做 DNS 与 HTTPS 可达性检查（合作方授权实验网）。",
            input_schema={
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}},
                    "context": {"type": "string"},
                },
                "required": ["targets"],
            },
            output_schema={"type": "object", "properties": {"run_id": {}, "results": {}, "summary": {}}},
            tags=["probe", "lab", "network"],
        ),
        _probe,
    )

    # 5. validate_graph_integrity
    def _validate(_: dict[str, Any]) -> dict[str, Any]:
        repo = get_graph_repository()
        g = repo.get_graph()
        vr = graph_engine.validate_graph(g["nodes"], g["edges"])
        md = build_validation_markdown()
        return {"validation": vr.model_dump(), "markdown": md}

    registry.register(
        SkillMetadata(
            name="validate_graph_integrity",
            display_name="Validate Graph Integrity",
            description="运行图谱完整性校验并返回结构化结果与 Markdown 报告。",
            input_schema={"type": "object", "properties": {}},
            output_schema={"type": "object", "properties": {"validation": {}, "markdown": {}}},
            tags=["graph", "report"],
        ),
        _validate,
    )

    # 6. build_demo_report
    registry.register(
        SkillMetadata(
            name="build_demo_report",
            display_name="Build Demo Report",
            description="根据当前图谱与系统状态构建 Demo 摘要 Markdown。",
            input_schema={"type": "object", "properties": {}},
            output_schema={"type": "object", "properties": {"markdown": {}}},
            tags=["report"],
        ),
        lambda _: {"markdown": build_demo_summary_md()},
    )

    # 7. create_experiment_task — 先作为占位，后续接 Neo4j 节点写入
    def _create_task(args: dict[str, Any]) -> dict[str, Any]:
        # TODO: 升级为写入 ExperimentTask 节点；当前仅回显输入用于前端演示。
        return {"created": True, "task": args}

    registry.register(
        SkillMetadata(
            name="create_experiment_task",
            display_name="Create Experiment Task",
            description="根据输入对象/方法/环境创建实验任务（示意版，仅回显）。",
            input_schema={"type": "object", "properties": {"title": {}, "target_entity": {}, "environment": {}, "method": {}, "status": {}, "owner": {}, "priority": {}, "notes": {}}},
            output_schema={"type": "object", "properties": {"created": {}, "task": {}}},
            tags=["experiment", "mutating"],
        ),
        _create_task,
    )

    def _run_worker_extraction(args: dict[str, Any]) -> dict[str, Any]:
        run_id = str(args.get("run_id", ""))
        run = trace_service.load_run(run_id)
        if not run:
            return {"error": "run not found"}
        return {"worker_results": run.get("worker_results", [])}

    registry.register(
        SkillMetadata(
            name="run_worker_extraction",
            display_name="Run Worker Extraction",
            description="读取指定 run 的 worker 抽取结果。",
            input_schema={"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            output_schema={"type": "object", "properties": {"worker_results": {}}},
            tags=["extraction", "worker"],
        ),
        _run_worker_extraction,
    )

    def _run_judge_scoring(args: dict[str, Any]) -> dict[str, Any]:
        run_id = str(args.get("run_id", ""))
        run = trace_service.load_run(run_id)
        if not run:
            return {"error": "run not found"}
        return {"judge": run.get("judge", {})}

    registry.register(
        SkillMetadata(
            name="run_judge_scoring",
            display_name="Run Judge Scoring",
            description="读取指定 run 的 judge 评分与冲突集。",
            input_schema={"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            output_schema={"type": "object", "properties": {"judge": {}}},
            tags=["extraction", "judge"],
        ),
        _run_judge_scoring,
    )

    def _run_conflict_repair(args: dict[str, Any]) -> dict[str, Any]:
        run_id = str(args.get("run_id", ""))
        run = trace_service.load_run(run_id)
        if not run:
            return {"error": "run not found"}
        return {"repair": run.get("repair")}

    registry.register(
        SkillMetadata(
            name="run_conflict_repair",
            display_name="Run Conflict Repair",
            description="读取指定 run 的 repair 结果。",
            input_schema={"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            output_schema={"type": "object", "properties": {"repair": {}}},
            tags=["extraction", "repair"],
        ),
        _run_conflict_repair,
    )

    def _create_staging_graph(args: dict[str, Any]) -> dict[str, Any]:
        run_id = str(args.get("run_id", ""))
        return trace_service.load_staging_graph(run_id) or {"error": "staging graph not found"}

    registry.register(
        SkillMetadata(
            name="create_staging_graph",
            display_name="Create Staging Graph",
            description="读取指定 run 的 staging graph（待审核子图）。",
            input_schema={"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            output_schema={"type": "object", "properties": {"run_id": {}, "nodes": {}, "edges": {}}},
            tags=["extraction", "staging"],
        ),
        _create_staging_graph,
    )

    def _validate_extraction_result(args: dict[str, Any]) -> dict[str, Any]:
        run_id = str(args.get("run_id", ""))
        run = trace_service.load_run(run_id)
        if not run:
            return {"error": "run not found"}
        return {"audit": run.get("audit", {})}

    registry.register(
        SkillMetadata(
            name="validate_extraction_result",
            display_name="Validate Extraction Result",
            description="读取 extraction audit 结果（确定性约束校验）。",
            input_schema={"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            output_schema={"type": "object", "properties": {"audit": {}}},
            tags=["extraction", "audit"],
        ),
        _validate_extraction_result,
    )

    def _merge_staging_graph(args: dict[str, Any]) -> dict[str, Any]:
        run_id = str(args.get("run_id", ""))
        staging = trace_service.load_staging_graph(run_id)
        if not staging:
            return {"error": "staging graph not found"}
        from app.schemas.extraction_pipeline import MergeRequest as ExtractionMergeRequest, StagingGraph

        req = ExtractionMergeRequest()
        merged = merge_service.merge_staging(run_id, StagingGraph.model_validate(staging), req)
        return merged.model_dump()

    registry.register(
        SkillMetadata(
            name="merge_staging_graph",
            display_name="Merge Staging Graph",
            description="将 staging graph 合并到主图谱（需人工确认后调用）。",
            input_schema={"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            output_schema={"type": "object", "properties": {"run_id": {}, "merged_nodes": {}, "merged_edges": {}}},
            tags=["extraction", "graph", "mutating"],
        ),
        _merge_staging_graph,
    )

    def _generate_extraction_report(args: dict[str, Any]) -> dict[str, Any]:
        run_id = str(args.get("run_id", ""))
        return {"run_id": run_id, "markdown": trace_service.load_report(run_id)}

    registry.register(
        SkillMetadata(
            name="generate_extraction_report",
            display_name="Generate Extraction Report",
            description="返回指定 run 的 Markdown 报告。",
            input_schema={"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            output_schema={"type": "object", "properties": {"run_id": {}, "markdown": {}}},
            tags=["extraction", "report"],
        ),
        _generate_extraction_report,
    )


_init_builtin_skills()

