# 3GPP Open Exposure Demo：项目全景、技术架构与技术路线

> 面向当前代码状态（backend + frontend）整理，聚焦“现在能做什么”和“下一步怎么演进”。

## 1) 这个项目现在能做什么

一句话概括：
**这是一个“标准知识结构化抽取 + 图谱驱动的暴露面候选分析 + 授权探测验证 + 报告输出”的端到端演示系统。**

### 1.1 已具备的核心能力

1. **图谱管理与可视化**
   - 统一管理 Service / NetworkFunction / Protocol / FQDNPattern / StandardDoc / RiskHypothesis 等实体与关系。
   - 支持图谱查看、统计、校验、邻域查询、导入导出、合并去重。
   - 前端使用 Cytoscape.js 提供交互式图谱页面。

2. **结构化抽取主线（Evidence-grounded + Human-in-the-loop）**
   - `POST /api/extraction/run` 启动完整抽取链路：
     - 文档切块 -> 证据包构建 -> 双 worker 并行抽取 -> judge 评分/冲突识别 -> 可选 repair -> staging graph。
   - 支持 trace、run 历史、staging diff、报告导出。
   - 通过 `POST /api/extraction/{run_id}/merge` 实现“人工确认后再入主图”。

3. **暴露面分析主线（Graph-driven Exposure Analysis）**
   - 基于图谱关系和 MCC/MNC 生成候选 FQDN、协议栈、网元关联、证据文档、风险假设。
   - 支持暴露面综合分析：候选 -> 风险评估（确定性 + 可选 LLM 保守解释）-> 攻击路径推演。
   - 支持 CSV 导出和分析报告落盘。

4. **授权探测能力（严格边界）**
   - 提供 DNS 解析 + HTTPS HEAD + 常见端口可达性检查。
   - 通过 allowlist/open policy 控制范围，明确仅限授权实验网。
   - 探测结果可回注到暴露面评估中，提升“候选”到“已验证路径”的可信度。

5. **Agent/Skill 编排能力**
   - Skill Registry 提供 MCP-like 工具发现与调用。
   - Agent 支持多步流程自动调度（抽取、合并、校验、报告）。
   - 前端可查看每一步 trace（输入、输出、状态、耗时）。

6. **报告与演示能力**
   - 图谱校验 Markdown、Mermaid 导出、Demo Summary。
   - 暴露面分析报告（run 级别）和抽取 run 报告自动持久化。

---

## 2) 技术架构梳理（从部署到模块）

### 2.1 总体分层

- **前端层（Vue 3 + Vite + TS）**
  - 页面：Dashboard / Graph / Extract / Exposure / AgentSkill / Reports / Experiments。
  - 状态管理：Pinia（图谱与抽取状态）。
  - 可视化：Cytoscape.js（图谱）、ECharts（统计）。

- **API 层（FastAPI）**
  - 路由模块：`graph`、`extract`、`extraction`、`exposure`、`probe`、`skills`、`agent`、`reports` 等。
  - 对外提供标准 REST 接口，前端通过 `/api/*` 调用。

- **服务编排层（Service / Orchestrator）**
  - `llm_orchestrator_service`：抽取流水线主控。
  - `exposure_service`：暴露面生成与综合分析。
  - `probe_service`：授权探测执行与策略控制。
  - `report_service` / `trace_service`：报告与运行轨迹落盘。

- **能力插件层（Skill + Agent）**
  - `skills/registry.py`：工具注册、schema、调用。
  - `agent/orchestrator.py`：多步骤自动执行与 trace。

- **数据与存储层**
  - 图谱仓储抽象：`GraphRepository`。
  - 实现 1：Neo4j（默认主后端）。
  - 实现 2：文件后端（JSON fallback）。
  - 运行时产物：`backend/data/runtime/*`（run、trace、report、staging、exposure_runs）。

### 2.2 关键设计点

1. **仓储抽象隔离存储差异**
   - 业务服务不直接耦合 Neo4j，统一走 repository 接口。
   - Neo4j 不可用时可自动降级到文件后端，保证演示可运行。

2. **“主图 + staging 子图”双轨**
   - 抽取结果先进入 staging，避免污染主图。
   - 人工确认后 merge，体现研究场景下的质量门控。

3. **证据优先的抽取与评估**
   - worker / judge / repair 都围绕 evidence pack 工作。
   - 避免仅靠“语义合理性”，强调可追溯和可解释。

4. **暴露面分析与探测解耦但可联动**
   - 先图谱推导候选（静态推理），再可选授权探测（动态验证）。
   - 两者拼接形成更完整的风险画像与路径验证状态。

---

## 3) 技术路线梳理（建议用“两条主线 + 一条支撑线”）

你提出的“两条主线”非常准确。更完整的表达建议如下：

- **主线 A：标准知识结构化提取与图谱沉淀**
- **主线 B：图谱驱动的暴露风险面分析与授权验证**
- **支撑线 C：Agent/Skill 编排与报告产品化**

### 3.1 主线 A：结构化提取与入图闭环

目标：把标准文本变成可计算、可审计、可复用的图谱知识。

阶段：
1. 输入文本与场景提示（IMS / VoWiFi / Open Gateway）。
2. 文档切块 + 检索，生成共享 evidence pack。
3. 双 worker 并行抽取（保守 vs 结构归纳）。
4. judge 进行结构化评分与冲突识别。
5. 针对冲突做字段级 repair（避免全量重跑）。
6. 形成 staging graph（带 provenance）。
7. 人工确认后 merge 到主图。

当前价值：
- 兼顾抽取质量、可追踪性、成本控制。
- 形成“模型输出 -> 人工审核 -> 知识资产沉淀”的闭环。

### 3.2 主线 B：暴露风险面分析与授权验证

目标：把“知识图谱”转化为“可行动的暴露候选与验证结论”。

阶段：
1. 基于服务 + MCC/MNC 从图谱推导候选 FQDN/协议/网元/证据/风险。
2. 生成候选清单并计算基础置信度。
3. 可选执行授权探测（DNS、HTTPS、端口与服务指纹）。
4. 生成风险评估（deterministic + 可选 LLM 保守解释）。
5. 推演攻击路径并给出验证状态（hypothesis/partially_validated/validated）。
6. 输出 run 级 JSON/Markdown/CSV 报告。

当前价值：
- 从“知识组织”走向“风险分析”。
- 从“静态候选”走向“带验证证据的风险结论”。

### 3.3 支撑线 C：编排与报告产品化

目标：把能力模块化并可被演示、复现、扩展。

现状：
- Skill 可发现、可单步运行。
- Agent 可自动串联抽取/合并/校验/报告。
- Dashboard + Reports 提供状态观测和成果交付。

意义：
- 让系统从“若干脚本”升级为“可操作平台原型”。

---

## 4) 现阶段定位（你可以对外这样讲）

**当前阶段定位：**
一个面向实验室与方案验证场景的“证据驱动知识工程 + 暴露面分析”中期原型，
强调授权边界、可解释链路和人机协同入图，不追求真实攻击能力。

**边界说明（重要）：**
- 不包含未授权扫描、漏洞利用、攻击自动化。
- 探测能力限定在授权实验网策略内。

---

## 5) 后续演进建议（按优先级）

1. **主线 A 先深化质量**
   - 完善 judge 评分阈值与自动回归集。
   - 增强 extraction audit 规则，补齐一致性校验。

2. **主线 B 强化“证据到结论”**
   - 风险评估从启发式进一步升级为规则模板 + LLM 双轨校核。
   - 攻击路径与实验任务打通（从路径自动生成实验任务草案）。

3. **支撑线 C 做可运维化**
   - run 数据生命周期管理、可检索报告索引。
   - Agent 增加可配置 planner（按目标动态选技能）。

4. **工程化**
   - 增加端到端测试样例（抽取 run、exposure run、probe 策略回归）。
   - 补齐关键 API 的契约测试和失败场景测试。

---

## 6) 最终总结（供汇报页直接引用）

该项目已经形成了从“标准文本 -> 结构化知识 -> 图谱沉淀 -> 暴露面候选 -> 授权验证 -> 报告交付”的完整演示链路。
其中，**结构化提取主线**负责构建高质量知识底座，**暴露面分析主线**负责把知识转化为风险洞察与验证结果，
并由 **Agent/Skill 与报告体系**作为工程化支撑，使系统具备持续演进为研究平台的基础。
