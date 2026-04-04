# 中期原型使用指南（给非通信背景同学）

这份文档按“你要做什么 → 点哪里 → 系统在背后做什么 → 怎么确认结果”来写。默认你已经完成：
- Neo4j 已启动（Docker）
- 后端与前端都能启动并访问 `http://localhost:5173`

---

## 0. 关键概念（用人话理解）

你在页面里看到的几个词，在系统里分别对应这些功能：

- **服务（Service）**：业务对象，如 `VoWiFi / IMS / Open Gateway`。
- **网元（NetworkFunction）**：网络中具体网元，如 `ePDG / N3IWF / P-CSCF / I-CSCF / S-CSCF`。
- **协议（Protocol）**：通信方式，如 `SIP / DNS / IKEv2 / IPsec / HTTPS / REST`。
- **命名规则（FQDNPattern）**：标准里“它可能长什么名字”的模板（例如 `ims.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org`）。
- **证据（StandardDoc / provenance）**：说明片段或标准编号（例如 `3GPP TS 23.003`）。
- **风险假设（RiskHypothesis）**：把潜在研究风险变成图谱可追踪的节点（例如“暴露式 FQDN 可能提升可发现性”）。
- **工具产物（WorkProduct）**：系统生成的报告、导出器、验证器等“可复用产物”。

系统把这些对象和关系统一存到图谱（Neo4j），再根据图谱生成“候选暴露面”和“实验任务建议”（展示向，不含未授权扫描）。

---

## 1. 启动与准备（Neo4j → 导入种子图谱）

### 1.1 启动 Neo4j

在项目根执行：

```powershell
cd e:\workplace\3gpp-open-exposure-demo\scripts
./start-neo4j.ps1
```

Neo4j Web 控制台：
- `http://localhost:7474`

默认账号：
- `neo4j / password`（本地开发用）

### 1.2 导入种子数据到 Neo4j

在后端目录执行，并确保环境变量指向 Neo4j：

```powershell
cd e:\workplace\3gpp-open-exposure-demo\backend

$env:EXPOSURE_GRAPH_BACKEND="neo4j"
$env:EXPOSURE_NEO4J_URI="bolt://localhost:7687"
$env:EXPOSURE_NEO4J_USER="neo4j"
$env:EXPOSURE_NEO4J_PASSWORD="password"

python scripts/import_to_neo4j.py
```

你应该看到类似：
- `Imported 50 nodes, 74 edges ...`

---

## 2. 启动后端与前端

### 2.1 后端（FastAPI）

```powershell
cd e:\workplace\3gpp-open-exposure-demo\backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2.2 前端（Vue）

```powershell
cd e:\workplace\3gpp-open-exposure-demo\frontend
npm install
npm run dev
```

浏览器打开：
- `http://localhost:5173`

API 文档：
- `http://localhost:8000/docs`

---

## 3. 系统怎么跑通（演示路径）

下面是 README 建议顺序的中期版本（对应你的系统能力）。

### 3.1 Dashboard：系统状态总览

- 看 `Neo4j 状态`：一般显示 `OK / 未就绪`。
- 看 `最近 Agent 运行`：展示 Agent 的执行 trace（如果你还没跑过 Agent，会是空表）。
- 看图谱统计卡片：节点/边数量、引用完整性、以及风险假设相关指标。

确认点：
- Dashboard 不报错，且 Neo4j 状态为 OK（说明图谱已经能被后端读取）。

---

### 3.2 知识图谱页（Graph）

你可以：
- 搜索节点
- 过滤节点类型 / 过滤关系类型
- 切换布局（Grid / Breadthfirst / CoSE）
- 点节点查看详情（右侧抽屉）
- 导出 PNG / JSON / Mermaid（前端已有按钮）

确认点：
- 点到 `IMS / ePDG / N3IWF / Open Gateway` 等节点，能看到它们的关联协议/命名模式/标准文档/风险。

---

### 3.3 标准抽取页（Extraction Workspace）

这一页默认走完整管线：
- 共享 Evidence Pack（top-k 检索片段）
- Worker A（保守） + Worker B（结构归纳）并行
- Judge 分项评分与 conflict set
- 可选字段级 repair
- 生成 staging graph（待人工确认）

确认点：
- 先在 staging graph 里确认，再点击 merge 入主图（human-in-the-loop）。

---

### 3.4 候选暴露面页（Exposure）

你输入：
- `服务`（VoWiFi / IMS / Open Gateway）
- `MCC=460`
- `MNC=001`

系统会基于图谱关系自动推导：
- 候选 FQDN（按命名规则模板拼 MCC/MNC）
- 协议栈（来自图谱中协议节点的关联）
- 依赖网元
- 证据文档
- 风险假设

确认点：
- VoWiFi 除了 `ePDG` 相关候选，还会生成 `N3IWF` 相关候选（种子关系已加）。

---

### 3.5 Agent / Skill 页（可编排研究工具平台）

你会看到两部分：

1) **Skill 列表**（MCP-like 工具发现）
- 后端提供：`GET /api/mcp/tools`
- 前端页面也会通过 `GET /api/skills` 展示当前注册的技能工具

2) **Agent 一键调度**
- 输入 `goal`（高层意图）
- 可选输入 `text`（标准说明片段）
- 点击运行后会展示 `trace`：每一步调用哪个 skill、输入是什么、输出是什么、耗时多少

当前 Agent 内置流程（演示版）：
- `extract_spec_knowledge` → `merge_graph_entities` → `validate_graph_integrity` → `build_demo_report`

确认点：
- 看到每一步状态为 ok，并且输出有结构化 JSON。

---

### 3.6 报告页（Reports）

你可以导出：
- 图谱校验 Markdown
- Mermaid 图谱
- Demo 摘要 Markdown

确认点：
- 校验报告能反映当前图谱是否有孤立节点/悬空边/未引用标准文档等。

---

## 4. 最小 API 调用示例（你也可以用这个“后台确认”）

### 4.1 查看系统状态

```powershell
curl http://localhost:8000/api/system/status
```

### 4.2 查看当前图谱统计

```powershell
curl http://localhost:8000/api/graph/stats
```

### 4.3 规则抽取

```powershell
curl -X POST http://localhost:8000/api/extract ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"IMS 与 SIP ...\"}"
```

### 4.4 混合抽取

```powershell
curl -X POST http://localhost:8000/api/extract/hybrid ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"Open Gateway 与 CAMARA ...\"}"
```

### 4.5 合并写入图谱

```powershell
curl -X POST http://localhost:8000/api/graph/merge ^
  -H "Content-Type: application/json" ^
  -d "{\"nodes\":[...],\"edges\":[...]}"
```

### 4.6 运行升级版 extraction pipeline

```powershell
curl -X POST http://localhost:8000/api/extraction/run ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"IMS 注册流程片段...\",\"scenario_hint\":\"IMS\",\"budget_mode\":\"default\"}"
```

查询 run：

```powershell
curl http://localhost:8000/api/extraction/<run_id>
curl http://localhost:8000/api/extraction/<run_id>/trace
curl http://localhost:8000/api/extraction/<run_id>/report
```

---

## 5. 故障排查（最常见两类）

### 5.1 Dashboard 显示 Neo4j 未就绪

通常是 Neo4j 容器没起来或端口不通。你可以：
- 打开 `http://localhost:7474` 看是否能登陆
- 确保后端启动时环境变量 `EXPOSURE_GRAPH_BACKEND=neo4j` 生效

### 5.2 LLM 结果为空

默认情况下 LLM 没配置时会返回空结构或 fallback 到规则。
你只需要：
- 配好 `backend/.env`（`EXPOSURE_LLM_PROVIDER / EXPOSE_LLM_BASE_URL / API_KEY` 等）
- 然后重启后端即可

---

## 6. 安全合规说明（非常重要）

系统不会做任何未授权的真实扫描/探测/漏洞利用。
“候选暴露面”是基于命名模板、证据与风险假设的研究性结构化候选，用于实验室内验证规划。

