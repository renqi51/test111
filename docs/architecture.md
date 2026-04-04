# 架构与扩展点

## 总览（中期原型）

系统目标：从标准/官方说明片段抽取实体与关系，写入图谱（Neo4j 为主），再基于图谱生成候选暴露面与实验任务，并提供可校验报告与可编排执行轨迹。

- **后端**：FastAPI 提供 REST API；图谱由 `GraphRepository` 抽象层统一访问：
  - **Neo4j**：默认图谱主存储（`backend/app/repositories/graph_repository.py`）
  - **文件**：作为 fallback / import-export（`backend/app/utils/storage.py`）
- **前端**：Vue 3 + Vite + TypeScript + Pinia + Element Plus；开发态通过 Vite **代理** `/api` 到本机 `8000` 端口。
- **分析**：`networkx` / `pandas` 用于校验与统计；图谱可视化在浏览器侧由 **Cytoscape.js** 完成。

## 可替换的存储层（Repository）

- 抽象层：`backend/app/repositories/graph_repository.py`
- 文件实现：`backend/app/utils/storage.py`

约束/建模策略（Neo4j）：
- 节点统一标签 `:Entity`，再叠加二级标签（`type` 对应二级标签）
- 唯一性约束：`Entity(id)` 唯一
- 基本导入去重：节点用 `MERGE`，边用 `(source)-[interaction]->(target)` 的合并

## 抽取管线（evidence-grounded + human-in-the-loop）

核心入口：
- `POST /api/extraction/run`
- `backend/app/services/llm_orchestrator_service.py`
- `backend/app/schemas/extraction_pipeline.py`

阶段化流程：
1. 输入接收（`DocumentInput`）
2. 预处理与切块（`DocumentChunk`）
3. 检索构造共享 `EvidencePack`（默认 top-k 受控）
4. Worker A（保守）与 Worker B（结构归纳）并行
5. Judge 结构化评分（schema/evidence/consistency/completeness/conservativeness）
6. 可选 repair（字段级，仅 conflict set）
7. 构造 staging subgraph（节点/边均带 provenance）
8. 前端人工确认后 merge 入主图
9. 输出 trace + markdown 报告

成本控制策略：
- 默认：2 worker + 1 judge
- 默认最多 1 轮 repair
- 仅在低分/高冲突或用户指定高精度时扩大预算

## Skill / Agent / MCP-like 工具发现

文件：
- `backend/app/skills/registry.py`：Skill Registry + MCP-like tool schema（`GET /api/mcp/tools`）
- `backend/app/agent/orchestrator.py`：Agent 执行与 step trace

技能目前已包含（并可扩展）：
- `extract_spec_knowledge`
- `merge_graph_entities`
- `query_graph_context`
- `generate_exposure_candidates`
- `validate_graph_integrity`
- `build_demo_report`
- `create_experiment_task`（下一步将写入 Neo4j 节点）
- `build_evidence_pack`
- `run_worker_extraction`
- `run_judge_scoring`
- `run_conflict_repair`
- `create_staging_graph`
- `validate_extraction_result`
- `merge_staging_graph`
- `generate_extraction_report`

前端可以通过：
- `Agent / Skill` 页面调用 `POST /api/agent/run`
- 查看每一步的输入/输出/耗时

## 报告与导出

- **校验 Markdown**：`report_service.build_validation_markdown()`，与 `scripts/validate_graph.py` 逻辑一致。
- **Mermaid**：`build_mermaid()`，节点 ID 中的 `-` 会替换为 `_` 以兼容 Mermaid 标识符。

## 前端数据流

- 图谱主数据：`GET /api/graph`，Pinia `graphStore` 缓存；合并后由 `merge` 响应直接更新 store。
- 演示页不硬编码业务节点表；统计与图表来自 `/api/graph/stats`、`/api/graph/validate`。

## 安全边界

- **不包含**对公网或未授权目标的端口扫描、漏洞利用或自动化攻击。
- Probe 仅限授权实验网场景，沿用 allowlist + DNS + HTTPS HEAD 约束。
- 抽取结果必须经过人工确认后才能进入主图。
- 「候选暴露面」仅生成 **命名/协议/证据/风险假设的结构化候选**，用于研究与实验室内验证规划。
