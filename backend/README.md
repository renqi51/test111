# Backend — 3GPP Open Exposure Demo

## 运行

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

首次启动会在 `data/runtime/graph_state.json` 从 `data/seed/*.csv` 初始化。

## 脚本

```bash
cd backend
python scripts/validate_graph.py
python scripts/export_mermaid.py -o ../docs/graph_export.mmd
python scripts/seed_graph.py
```

## API 摘要

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/system/status` | 系统状态（图谱后端 / LLM / Agent） |
| GET | `/api/graph` | 全量图谱 |
| GET | `/api/graph/stats` | 统计 |
| GET | `/api/graph/node/{id}` | 单节点信息 |
| GET | `/api/graph/neighbors/{id}` | 邻居子图 |
| POST | `/api/graph/validate` | 校验 |
| POST | `/api/graph/merge` | 合并抽取结果 |
| POST | `/api/extract` | 规则抽取 |
| POST | `/api/extract/hybrid` | 规则 + LLM 混合抽取 |
| GET | `/api/extract/samples` | 示例文本 |
| POST | `/api/exposure/generate` | 候选暴露面 |
| POST | `/api/exposure/export_csv` | CSV 导出 |
| GET | `/api/reports/validation` | Markdown 校验报告 |
| GET | `/api/reports/mermaid` | Mermaid 文本 |
| GET | `/api/reports/demo_summary_md` | Demo 摘要 MD |
| GET | `/api/demo/summary` | Demo 摘要 JSON |
| GET | `/api/experiments` | 实验任务 mock |
| GET | `/api/skills` | 列出已注册技能（MCP-like） |
| POST | `/api/skills/run` | 手动运行某个 skill |
| POST | `/api/agent/run` | 让 Agent 按预设流程调用多个 skill |
| GET | `/api/agent/runs` | Agent 历史运行列表 |
| GET | `/api/agent/runs/{run_id}` | Agent 单次运行详情 |

## 存储扩展

图数据通过 `app/repositories/graph_repository.py` 访问：

- 默认使用 **Neo4j**（环境变量 `EXPOSURE_GRAPH_BACKEND=neo4j` 且连接正常）；
- 若 Neo4j 未就绪，则自动回退到 **文件存储**（`data/runtime/graph_state.json`，由 `app/utils/storage.py` 管理）。

Neo4j 推荐用项目根目录的 `docker-compose.neo4j.yml` + `scripts/start-neo4j.ps1` 一键启动。

