# 3GPP Open Exposure Demo 后端模块技术与策略

## 1. 后端总体总结（面向汇报）

后端是本项目的“能力中枢”，核心目标是把标准文本处理、图谱管理、暴露面分析、授权探测、Agent 编排与报告导出统一到一套可追溯 API 体系中。

端到端链路如下：

1. 接收标准输入并执行结构化抽取（evidence-grounded）。
2. 抽取结果先写 staging graph，人工确认后 merge 主图。
3. 基于图谱与 MCC/MNC 生成候选暴露面并关联证据。
4. 在授权策略内执行 DNS/HTTPS 探测并回注分析。
5. 输出 run 级 JSON/Markdown/CSV 与 trace，用于复盘和交付。

后端不是“单个问答服务”，而是“知识工程 + 风险分析 + 平台编排”的复合系统。

---

## 2. 后端技术栈与总体架构

## 2.1 技术栈

- 框架：FastAPI
- 语言与模型：Python 3.11 + Pydantic
- 图计算：networkx / pandas（统计与校验）
- 图存储：Neo4j（主）+ 文件后端（fallback）
- 向量检索：Milvus（GraphRAG）
- 大模型接入：OpenAI-compatible HTTP API（含重试、并发闸门、可流式）

## 2.2 分层结构

1. **API 层**（`app/api/*.py`）：对外 REST 接口与参数校验。
2. **服务层**（`app/services/*.py`）：抽取编排、暴露分析、探测、报告、GraphRAG。
3. **仓储层**（`app/repositories/graph_repository.py`）：图存取抽象与后端切换。
4. **能力注册层**（`app/skills/registry.py` + `app/agent/orchestrator.py`）：Skill 发现与 Agent 调度。
5. **配置与运行时层**（`app/core/config.py` + `data/runtime/*`）：配置治理与运行产物沉淀。

---

## 3. 后端模块拆解（技术 + 策略）

## 3.1 应用入口与系统状态（`main.py`）

**技术实现**
- 启动时初始化 seed/runtime 与图仓储。
- 自动挂载 graph/extraction/exposure/probe/agent/reports/graph-rag 等路由。
- 提供 `/api/system/status` 聚合后端运行态（图后端、LLM、Agent、probe、extraction 参数）。

**策略**
- 启动即自检：保障“演示可用性”优先。
- 状态可观测：前端 Dashboard 可直接读取运行健康信息。

## 3.2 图谱管理模块（`api/graph.py` + `services/graph_engine.py`）

**技术实现**
- 提供全图读取、统计、校验、邻域查询、子图检索、CSV 导入、JSON 导出。
- `graph_engine` 负责 merge 预览与完整性校验逻辑。

**策略**
- 图谱作为“统一真相层”：所有业务链路都依赖图谱而非散落文本。
- 子图优先：为大图场景保留性能可控的查询路径。

## 3.3 仓储抽象与双后端策略（`repositories/graph_repository.py`）

**技术实现**
- 抽象接口 `GraphRepositoryBase`，实现 `Neo4jGraphRepository` 与 `FileGraphRepository`。
- Neo4j 使用 `MERGE` + 约束防重复；fallback 文件后端保证最低可运行。
- 支持 staging 图读写（Neo4j best-effort + file copy 兜底）。

**策略**
- 去耦存储：业务服务不直接依赖 Neo4j 细节。
- 降级可运行：数据库异常时仍可进入演示流程。

## 3.4 抽取编排模块（`api/extraction.py` + `services/llm_orchestrator_service.py`）

**技术实现**
- 主入口 `POST /api/extraction/run`，执行：
  `ingest -> chunk -> retrieval/evidence -> worker_a+b -> judge -> repair -> staging -> report`。
- 提供 run 列表、详情、trace、report、repair、merge、staging-diff。

**策略**
- 证据优先：worker/judge/repair 围绕 Evidence Pack 协同。
- 成本约束：预算模式、top_k、repair 轮数可配置。
- 质量门控：默认 staging + human-in-the-loop，避免主图污染。

## 3.5 追踪与运行产物模块（`services/trace_service.py`）

**技术实现**
- 持久化 run、trace、report、evidence_pack、staging_graph。
- 提供 latest run 与历史摘要列表。

**策略**
- 全链路可审计：每次抽取可回放、可对比、可归档。
- 交付友好：报告与 trace 可以直接用于汇报材料。

## 3.6 暴露面分析模块（`api/exposure.py` + `services/exposure_service.py`）

**技术实现**
- 支持候选生成、CSV 导出、综合分析、run 查询、报告读取。
- 综合分析包含：
  图谱推导（模式/协议/网元/证据/风险）+ probe 回注 + deterministic 评分 + 可选 LLM 解释 + attack path 构建。

**策略**
- “知识到结论”闭环：不仅列候选，还给出风险与验证状态。
- 合规边界前置：所有动态探测均在授权策略下运行。

## 3.7 探测模块（`api/probe.py` + `services/probe_service.py`）

**技术实现**
- 提供 probe 状态、最近运行、按目标批量探测。
- 输出每个目标的 policy / DNS / HTTPS / 端口 / 指纹信息。

**策略**
- 强策略约束：allowlist/open 模式受配置控制。
- 保守执行：强调“授权实验网验证”，不扩展到未授权扫描。

## 3.8 GraphRAG 模块（`api/graph_rag.py` + `services/graph_rag_*`）

**技术实现**
- `ingest-text`：文本切块、抽取并入 Milvus。
- `query`：混合上下文问答（图子图 + chunk 检索）。
- `query-stream`：流式返回增量答案事件。
- 答案层做结构化容错，避免因模型字段类型漂移导致整次失败。

**策略**
- 混合检索：图结构上下文负责关系骨架，文本上下文负责细节证据。
- 体验优先：支持流式输出，降低等待感。
- 稳定优先：对 LLM 输出做 schema 归一化，提升线上鲁棒性。

## 3.9 LLM Provider 模块（`providers/llm_provider.py`）

**技术实现**
- 统一 `chat_json` 与 `chat_stream_text` 能力。
- 内置超时、重试、并发闸门、状态码分级处理。
- Null provider 兼容未配置场景。

**策略**
- 接入抽象统一：上层服务不关心具体厂商协议差异。
- 稳定性优先：通过重试与限流降低外部 API 抖动冲击。

## 3.10 Skill / Agent 平台模块（`api/skills.py`、`api/mcp.py`、`api/agent.py`）

**技术实现**
- Skill 注册中心提供工具发现与执行（MCP-like schema）。
- Agent orchestrator 支持多步技能调用与 step trace 记录。
- 对外提供运行历史与单次详情查询。

**策略**
- 平台化扩展：能力按 skill 挂载，后续新增模块可低成本接入。
- 透明执行：Agent 每一步输入/输出可视，可审阅、可复盘。

## 3.11 报告模块（`api/reports.py` + `services/report_service.py`）

**技术实现**
- 导出 validation markdown、mermaid、demo summary。
- 作为统一成果出口服务前端 Reports 页。

**策略**
- 交付导向：研究输出必须具备“可读、可导出、可复现”属性。

## 3.12 本地批量构建模块（`api/builder.py` + `services/kg_builder_service.py`）

**技术实现**
- `run-local-import` 支持按文件批量构建图谱（含 dry-run/扩展名筛选）。

**策略**
- 兼顾离线导入与在线问答：既支持日常迭代，也支持汇报前快速重建。

---

## 4. 后端工程策略（跨模块）

## 4.1 架构策略

- 分层明确：API 只编排，不堆业务逻辑；服务层承担核心能力；仓储层隔离存储差异。
- 模块化路由：每个业务域独立路由，便于持续扩展。

## 4.2 稳定性策略

- 图后端自动降级（Neo4j -> file）。
- LLM 接入重试 + 限流 + 错误分类。
- 关键链路落盘 run/trace/report，异常可回放定位。

## 4.3 数据治理策略

- 运行产物统一写入 `data/runtime/*`，便于审计与清理。
- staging 与 main 分离，防止低质量结果直接入库。

## 4.4 可解释性策略

- 抽取流程保留 evidence/judge/conflict/repair 信息。
- 暴露面分析保留证据引用与路径推演。
- GraphRAG 保留 citations 并支持结构化输出。

## 4.5 合规与安全策略

- 明确 probe 只面向授权实验网。
- 不提供未授权扫描或利用能力。
- UI 与 API 都持续暴露策略状态，降低误操作风险。

---

## 5. 后端当前定位与后续建议

## 5.1 当前定位

后端已具备“研究原型平台”形态：  
从知识抽取到分析报告的全链路可运行、可观测、可审核、可导出。

## 5.2 后续建议（后端）

1. 增加统一诊断端点（检索命中数、prompt 长度、模型耗时、失败类型）。
2. 建立 run 生命周期管理（归档、压缩、索引检索、过期清理）。
3. 对 GraphRAG 建立 A/B 评测接口（GraphRAG vs plain RAG）便于量化证明。
4. 增加关键 API 契约测试与端到端回归集，保证演示稳定性。
5. 将 Agent 从固定流程升级为可配置 planner（按 goal 动态选 skill）。

---

## 6. 一句话结论（可直接用于答辩）

本项目后端以“稳定可运行、证据可追溯、策略可约束、结果可交付”为核心设计原则，构建了从标准知识工程到暴露面分析验证的可扩展平台底座。

