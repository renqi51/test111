# 3GPP Open Exposure Demo：从 0 到 1 技术实现全记录

> 文档目标：把项目从“没有系统”到“可演示原型”的技术路径完整讲清楚，重点覆盖**架构设计**、**实现做法**、**信息流（Data/Control Flow）**。  
> 适用对象：项目维护者、接手开发同学、答辩/汇报准备人员。

---

## 1. 项目起点与目标定义

### 1.1 起点问题

项目最初要解决的是一个“断层”问题：  
3GPP/GSMA 标准内容很多、术语复杂、跨文档关联强，但实际做暴露面分析时，团队往往只能靠人工阅读和经验拼接，难以复现和审计。

### 1.2 0->1 目标

从 0 开始，本项目把目标拆成三层：

1. **知识层**：把标准文本变成结构化实体/关系（而不是散落文档笔记）。  
2. **分析层**：从图谱自动推导候选暴露面，并形成可解释风险结论。  
3. **工程层**：做成可运行平台（UI + API + 报告 + 运行轨迹），支持演示和迭代。

### 1.3 边界约束

项目明确设置安全边界：只做授权实验网内的研究验证，不包含未授权扫描、漏洞利用或攻击自动化。

---

## 2. 从 0 到 1 的演进路线

### 阶段 A：先跑通“最小闭环”

- 建后端 API（FastAPI）和前端面板（Vue 3）。
- 用种子 CSV 初始化图谱，至少能完成：读取图谱、统计、校验、可视化。
- 用文件运行时存储保证“无外部依赖时也能跑通”。

**阶段成果**：系统有了最小可演示骨架（图谱浏览 + 基础报告）。

### 阶段 B：引入真实知识生产链路（Extraction Pipeline）

- 增加 `evidence-grounded` 抽取链路：输入 -> 切块 -> 检索 -> 双 worker -> judge -> 可选 repair。
- 引入 `staging graph`，先落待审核子图，再人工确认 merge 入主图。
- 增加 run/trace/report 持久化，形成可追溯审计能力。

**阶段成果**：系统从“静态图谱展示”升级为“可持续增量建图”的平台。

### 阶段 C：把知识转成风险分析与验证

- 基于图谱关系生成候选 FQDN、协议栈、网元依赖、证据映射、风险假设。
- 加入授权探测（DNS/HTTPS/端口）并回注候选状态。
- 输出 run 级 JSON/Markdown/CSV 报告，形成演示交付件。

**阶段成果**：形成“标准知识 -> 候选暴露面 -> 验证证据 -> 风险结论”的业务链。

### 阶段 D：平台化（Agent / Skill / GraphRAG）

- 加入 Skill 注册与 Agent 编排，支持高层 goal 触发多步任务。
- 增加 GraphRAG 相关入口（图子图检索 + 文本检索上下文）。
- 前端新增 Dashboard、Agent、Reports 等页面，支持状态观测与复盘。

**阶段成果**：原型具备平台化雏形，而不只是单点脚本。

---

## 3. 当前总体架构（落地实现）

## 3.1 技术栈

- 后端：Python 3.11 + FastAPI + Pydantic + networkx + pandas。
- 前端：Vue 3 + Vite + TypeScript + Pinia + Element Plus + Cytoscape.js + ECharts。
- 图存储：Neo4j（主） + 文件后端（fallback）。
- 运行产物：`backend/data/runtime/*`（run、trace、report、staging、exposure_runs）。

## 3.2 分层架构

1. **UI 层（frontend）**  
   路由聚合 Dashboard、Graph、Extract、Exposure、Agent、Reports、GraphRAG、Experiments 页面。

2. **API 层（backend/app/api）**  
   对外暴露 `/api/*`，负责参数校验、调用服务、返回结构化结果。

3. **服务编排层（backend/app/services）**  
   承担核心业务：抽取编排、图谱校验、暴露面分析、probe、报告生成、trace 持久化。

4. **仓储层（backend/app/repositories）**  
   `GraphRepository` 抽象图存取，屏蔽 Neo4j 与文件实现差异。

5. **数据层（backend/data）**  
   `input/rule` 做抽取输入与规则上下文。

## 3.3 关键设计原则

- **双后端容错**：Neo4j 不可用时自动回退文件后端，保证演示可运行。
- **主图/暂存分离**：抽取先入 staging，人工确认后 merge，降低污染主图风险。
- **证据优先**：worker/judge/repair 围绕 evidence pack 工作，强调可追溯。
- **报告先行**：每次运行写 trace + report，确保可审计、可复盘、可汇报。

---

## 4. 核心做法（How）

## 4.1 启动与初始化做法

应用启动时做三件关键事：

1. 初始化本地 seed/runtime（兜底）。  
2. 初始化图仓储（优先 Neo4j，失败回退文件）。  
3. 预加载规则上下文，保证后续抽取可用。

这样做的好处是：即使外部依赖不完整，系统仍可进入“可演示”状态。

## 4.2 图谱建模做法

- 节点统一走 `Entity(id)` 约束，属性包含 `type/label/description/evidence_source` 等。
- 边使用 `(source)-[interaction]->(target)` 模式表达关系。
- 合并逻辑优先去重与幂等（`MERGE` 语义），避免重复导入污染。

## 4.3 抽取管线做法（升级主线）

`POST /api/extraction/run` 的真实链路：

1. 文档输入标准化（`DocumentInput`）。
2. 文档切块（`DocumentChunk`）。
3. 构建共享 `EvidencePack`（支持策略与 top-k 调整）。
4. 并行执行 Worker A/B。
5. Judge 评分与冲突识别。
6. 需要时执行字段级 Repair（默认最多 1 轮）。
7. 生成 staging graph（携 provenance）。
8. 保存 run/trace/report，并输出前端可消费结果。

这条链路对应“质量与成本平衡”的设计：默认 2 worker + 1 judge，在预算内提升可解释质量。

## 4.4 Human-in-the-loop 做法

- 抽取结果不直接进主图。
- 通过 `POST /api/extraction/{run_id}/merge` 完成人工确认后的合并。
- 支持 `staging-diff` 对比新旧节点/边，给出“new/existing”视图。

该机制是项目可信性的核心抓手，尤其适合研究演示场景。

## 4.5 暴露面分析做法

`analyze_exposure()` 采用“图谱推导 + 可选探测 + 风险评估”三段式：

1. 从服务节点出发，沿关系推导命名模式、协议、网元、风险和证据。  
2. 结合 MCC/MNC 渲染候选 FQDN。  
3. 可选调用 probe（授权范围内）回注候选状态。  
4. 先做 deterministic 风险打分，再可选 LLM 保守解释。  
5. 生成攻击路径假设与验证状态，落盘 JSON/Markdown 报告。

## 4.6 前端实现做法

- 通过 Vite 代理 `/api` 到后端，开发态零跨域阻碍。
- Pinia 中 `graphStore` 统一管理图谱状态，支持全量加载、子图搜索、邻域扩展、合并缓存。
- 路由懒加载页面，降低首屏负担，利于演示体验。

---

## 5. 信息流（What flows where）

## 5.1 全局信息流总览

1. 用户在前端发起操作（页面按钮/表单）。  
2. 前端通过 `axios client` 调用 `/api/*`。  
3. API 路由把请求交给服务层编排。  
4. 服务层读取/写入图仓储与运行时产物。  
5. 结果回到前端 store，驱动视图更新与导出。

## 5.2 抽取信息流（端到端）

- **输入流**：文本/标题/场景提示 -> `ExtractionRunRequest`。  
- **处理中间流**：chunks -> evidence pack -> worker results -> judge -> repair -> staging。  
- **持久化流**：`runtime/extraction_runs`、`runtime/traces`、`runtime/reports`、`runtime/staging_graphs`。  
- **确认流**：用户审核 staging -> merge -> 主图更新。  
- **反馈流**：前端拉取 run 详情、trace、report，展示流程证据链。

## 5.3 暴露面分析信息流

- **输入流**：service + MCC/MNC + 探测选项。  
- **推导流**：图关系解析 -> FQDN 候选 -> 证据/风险绑定。  
- **验证流**：probe 结果注入 candidate `probe_status`。  
- **评估流**：deterministic + optional LLM -> assessment。  
- **输出流**：attack paths + summary + run 报告（JSON/MD/CSV）。

## 5.4 图谱查询信息流

- `GET /api/graph`：主图全量。  
- `GET /api/graph/subgraph/search`：按关键词找子图（大图性能优化关键入口）。  
- `GET /api/graph/neighbors/{id}`：围绕节点做局部扩展。  
- 前端 `graphStore` 采用 merge 方式更新，降低重复渲染与状态抖动。

---

## 6. 关键模块与职责地图

### 后端核心

- `app/main.py`：启动、路由挂载、系统状态。
- `app/repositories/graph_repository.py`：图仓储抽象 + Neo4j/file 双实现。
- `app/services/llm_orchestrator_service.py`：抽取主编排器。
- `app/services/exposure_service.py`：暴露面分析主服务。
- `app/services/trace_service.py`：run/trace/report/staging 持久化。
- `app/api/extraction.py`：抽取相关 API（run/detail/trace/report/repair/merge）。
- `app/api/graph.py`：图谱读取、校验、合并、子图查询、导入导出。

### 前端核心

- `src/router/index.ts`：页面路由。
- `src/api/client.ts`：统一 HTTP 客户端。
- `src/stores/graphStore.ts`：图谱状态与子图加载逻辑。
- `src/views/*`：Graph/Extract/Exposure/Agent/Reports 等业务页面。

---

## 7. 这套做法为什么成立

1. **先可运行，再增强**：先保 demo 可跑，再逐步叠加复杂能力，避免大而全失败。  
2. **抽象隔离外部依赖**：仓储层抽象让 Neo4j 不成为单点阻塞。  
3. **质量门控清晰**：worker/judge/repair + staging merge 的链路可控、可审计。  
4. **证据链完整**：trace/report/run 让每次输出可解释，可复核。  
5. **平台化扩展位充足**：Agent/Skill/GraphRAG 已形成可拓展接口面。

---

## 8. 当前局限与下一步建议

### 局限

- 抽取质量仍依赖 prompt 与规则上下文覆盖度。
- 暴露面评分含启发式成分，行业化规则库仍需持续沉淀。
- 运行产物增多后，缺统一生命周期管理与索引检索。

### 建议

1. 增加抽取/暴露面端到端回归集，固化“每次修改不退化”。  
2. 把风险评分升级为“规则模板 + LLM 双轨一致性校核”。  
3. 增加 run 数据归档与检索，提升长期运维可用性。  
4. 把实验任务从 mock 推进到可执行编排（仍保持授权边界）。

---

## 9. 复现这个 0->1 过程的最小操作清单

1. 启动后端与前端（必要时先启动 Neo4j）。  
2. 检查 `/api/system/status` 确认图后端与 LLM 状态。  
3. 从 Graph 页确认主图可读、统计可用。  
4. 在 Extract 页跑一条抽取，观察 trace/report/staging。  
5. 审核后执行 merge，确认主图增量变化。  
6. 在 Exposure 页生成候选并导出报告。  
7. 在 Agent/Reports 页完成全链路展示与复盘。

完成以上 7 步，即可完整复现本项目从“知识构建”到“分析输出”的端到端价值链。

