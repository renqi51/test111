# 大模型辅助的 3GPP 开放服务暴露面发现与实验验证工具（原型 Demo）

本地可运行的前后端分离原型：**知识图谱 + evidence-grounded 抽取管线 + staging graph 人工确认入图 + 候选暴露面生成 + 校验报告 + Agent/Skill 编排**。面向实验室汇报，**不包含未授权扫描能力**。

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Python 3.11、FastAPI、Pydantic、pandas、networkx、uvicorn |
| 前端 | Vue 3、Vite、TypeScript、Pinia、Element Plus、Cytoscape.js、ECharts、axios |
| 数据 | 种子 CSV + 运行时 JSON（`backend/data/runtime/graph_state.json`） |

## 一键启动（开发）

**终端 1 — 后端**

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**终端 2 — 前端**

```powershell
cd frontend
npm install
npm run dev
```

浏览器打开 **`http://localhost:5173`**。API 文档：`http://localhost:8000/docs`。

> 生产构建：在 `frontend` 执行 `npm run build`，将 `dist` 交由任意静态服务器；需反向代理 `/api` 到后端。

## 演示路径（建议顺序）

1. **Dashboard**：看系统状态（Neo4j / LLM / Agent）、图谱规模、风险/完整性指标、最近 Agent 运行列表。
2. **知识图谱**：过滤类型/关系，切换布局，点节点查看证据与关联。
3. **Extraction Workspace**：输入标准片段，启动 `2 worker + 1 judge`，查看 Evidence Pack、Worker A/B、Judge 评分、Conflict Set、Repair、Staging Graph。
4. **人工确认合并**：在 staging graph 页面确认后再 merge into main graph（human-in-the-loop）。
5. **候选暴露面**：选 VoWiFi / IMS / Open Gateway，输入 MCC=460、MNC=001 → 基于 Neo4j 图谱生成候选并导出 CSV。
6. **Agent / Skill**：输入高层 goal，让 Agent 自动调用多个 Skill，并查看每一步 trace。
7. **报告页**：导出抽取 run 报告、图谱校验 Markdown、Mermaid、Demo 摘要等。

## 抽取管线（升级版）

`POST /api/extraction/run` 会触发完整链路：

1. 输入统一封装（`DocumentInput`）
2. 文档切块（`DocumentChunk`）
3. 统一检索并生成共享 `EvidencePack`
4. Worker A（保守）/ Worker B（结构归纳）并行抽取
5. Judge 结构化评分与 conflict set
6. 可选字段级 repair（不全量重跑）
7. 构造 staging graph（带 provenance）
8. 人工确认后 `POST /api/extraction/{run_id}/merge` 入主图

支持端点：
- `POST /api/extraction/run`
- `GET /api/extraction/{run_id}`
- `GET /api/extraction/{run_id}/trace`
- `GET /api/extraction/{run_id}/report`
- `POST /api/extraction/{run_id}/repair`
- `POST /api/extraction/{run_id}/merge`
- `GET /api/extraction/prompts`
- `GET /api/extraction/status`

## 目录结构

```
3gpp-open-exposure-demo/
  backend/           # FastAPI 应用、种子数据、脚本
  frontend/          # Vue SPA
  docs/              # 架构说明与摘要
```

## 后端脚本

```powershell
cd backend
python scripts/validate_graph.py
python scripts/export_mermaid.py -o ..\docs\graph_export.mmd
python scripts/seed_graph.py
```

`seed_graph.py` 会用种子 CSV **覆盖**运行时图谱。

## Neo4j（中期版）

如果你已用 Docker 启动 Neo4j：

1. 导入种子图谱到 Neo4j：

```powershell
cd backend
$env:EXPOSURE_GRAPH_BACKEND="neo4j"
$env:EXPOSURE_NEO4J_URI="bolt://localhost:7687"
$env:EXPOSURE_NEO4J_USER="neo4j"
$env:EXPOSURE_NEO4J_PASSWORD="password"
python scripts/import_to_neo4j.py
```

2. 然后启动后端/前端即可从 `/api/graph` 直接读取 Neo4j 图谱。

## 种子数据规模

约 **50** 个节点、**73** 条边（可在 `backend/data/seed` 中扩展）。

## 文档

- [架构与扩展点](docs/architecture.md)
- [Demo 摘要（静态）](docs/demo_summary.md)

## 声明

本项目仅用于**教育与研究演示**。Probe 仅面向授权实验网场景；系统不包含未授权扫描能力。使用者需遵守当地法律与目标环境授权要求；作者不对滥用行为负责。
