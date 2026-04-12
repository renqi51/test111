# 系统用途与用法说明

本文档概括 **3GPP 开放服务暴露面发现与实验验证（原型 Demo）** 的定位、典型用法与关键操作入口，便于新成员快速上手。更细的界面级步骤见 [`usage_guide_midstage.md`](usage_guide_midstage.md)；架构与模块策略见 [`architecture.md`](architecture.md)、[`project_overview_and_tech_route.md`](project_overview_and_tech_route.md)。

---

## 一、系统用途（解决什么问题）

本系统面向 **授权实验网 / 教学汇报** 场景，将 3GPP 与开放网关相关规范中的**合法业务架构**结构化进知识图谱，并在此基础上串联：

| 能力 | 说明 |
|------|------|
| **知识图谱（Neo4j / 文件回退）** | 存储网元、协议、接口、FQDN 模式、风险假设等实体及关系；支持从文档抽取结果经 staging 合并入图。 |
| **向量检索（Milvus + GraphRAG）** | 对规范切片建向量索引；问答时结合 Neo4j 子图与 Milvus 召回片段，生成有据可查的回答。 |
| **暴露面候选生成** | 按服务（如 VoWiFi、IMS、Open Gateway）与 MCC/MNC 等参数，基于图谱推导候选暴露点并导出 CSV。 |
| **授权探测（Probe）** | 在策略白名单内对目标做 DNS/HTTPS/UDP/TCP/SCTP/SBI 等可达性观测，为红队分析提供事实输入。 |
| **沙箱验证（Sandbox）** | 对经校验的 shell 命令在受限环境中执行，避免未授权目标与危险操作。 |
| **ReAct Agent** | 按固定链路编排：probe → graph_rag → synthesize → execute_verify → finish，结论需有沙箱证据支撑。 |
| **静态威胁剧本（ThreatVector）** | 从 JSON 确定性挂载到 Neo4j，与网元 `Entity` 建立 `VULNERABLE_TO` 边；GraphRAG 将 `payload_template` 以 verbatim 形式交给 Agent，便于与 probe 结果装配后送沙箱。 |

**非目标**：不提供对未授权目标的扫描能力；生产级渗透工具链不在本仓库范围内。

**合规声明**：仅用于教育、研究与授权环境下的演示；使用者需自行确保目标与操作合法。详见仓库根目录 [`README.md`](../README.md) 中的声明。

---

## 二、运行环境与依赖

- **Python 3.11+**（后端 `backend/requirements.txt`）
- **Node.js**（前端构建与开发服务器）
- **Neo4j**（推荐）：`EXPOSURE_GRAPH_BACKEND=neo4j`，连接失败时回退到 `backend/data/runtime/graph_state.json`
- **Milvus**（可选，用于 GraphRAG 向量召回）：按 `app/core/config` 中 GraphRAG 相关环境变量配置
- **LLM API**（可选）：未配置时部分抽取、Agent、GraphRAG 回答能力受限，但图谱浏览与部分 API 仍可用

---

## 三、快速启动（开发）

### 3.1 后端

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- OpenAPI 交互文档：`http://localhost:8000/docs`
- 系统状态（图谱后端 / LLM / Agent 等）：`GET /api/system/status`

### 3.2 前端

```powershell
cd frontend
npm install
npm run dev
```

浏览器访问：`http://localhost:5173`（开发服务器默认端口以 Vite 输出为准）。

### 3.3 Neo4j 与种子图（推荐顺序）

1. 启动 Neo4j（例如项目内 `docker-compose.neo4j.yml` 或 `scripts/start-neo4j.ps1`，路径以本仓库为准）。
2. 设置环境变量后导入种子数据，例如：

```powershell
cd backend
$env:EXPOSURE_GRAPH_BACKEND="neo4j"
$env:EXPOSURE_NEO4J_URI="bolt://localhost:7687"
$env:EXPOSURE_NEO4J_USER="neo4j"
$env:EXPOSURE_NEO4J_PASSWORD="password"
python scripts/import_to_neo4j.py
```

3. 若使用 **GraphRAG 向量库**，需先完成规范入库与向量构建（参见 [`scripts/build_graphrag_from_existing_graph.py`](../backend/scripts/build_graphrag_from_existing_graph.py) 及后端 README 中的说明）。

---

## 四、主要用法（按角色）

### 4.1 产品 / 汇报演示

1. Dashboard：查看 Neo4j、LLM、Agent 状态与图谱规模。
2. 知识图谱页：浏览实体与关系、证据字段。
3. 暴露面：选择服务类型与 MCC/MNC，生成候选并导出 CSV。
4. 报告：校验报告、Mermaid、Demo 摘要 Markdown 等 API 或前端入口。

### 4.2 图谱与抽取研发

- **LLM 抽取管线**：`POST /api/extraction/run` 等（详见根 `README.md` 抽取端点列表）；staging 确认后 merge 入主图。
- **规则/混合抽取**：`POST /api/extract`、`POST /api/extract/hybrid`。
- **图校验**：`POST /api/graph/validate`；脚本示例见 [`backend/README.md`](../backend/README.md)。

### 4.3 GraphRAG 与威胁剧本

- 问答入口：后端 GraphRAG 服务在混合检索时会拉取 Neo4j 子图；若网元上挂载了 **ThreatVector**，响应中会包含 **`threat_vectors_verbatim`**（含图库原文 **`payload_template`**），并在提示词中以 `THREAT_VECTOR_VERBATIM_JSON` 区块呈现，要求模型不得擅自改写标点。
- **静态剧本入库**（不清空 Neo4j、不覆盖 Milvus）：

```powershell
cd backend
python scripts/ingest_threat_intel.py --dry-run
python scripts/ingest_threat_intel.py
python scripts/ingest_threat_intel.py --path data/threat_intel/playbooks.json --print-json
```

默认读取：`backend/data/threat_intel/playbooks.json`。非 Neo4j 后端时脚本会以非零退出码提示。

### 4.4 红队编排 Agent（ReAct）

- API：`POST /api/agent/run`（及 runs 查询类接口，见 `backend/README.md`）。
- 行为要点：必须先 probe，再 graph_rag，再 synthesize，再 **execute_verify**（沙箱），成功执行后才允许 **finish**；若 GraphRAG 返回了带占位符的 `payload_template`，系统提示要求用 **Python 字符串替换** 将 probe 得到的真实 IP/参数填入模板后再提交沙箱。

---

## 五、目录与文档索引

| 路径 | 说明 |
|------|------|
| `backend/app/` | FastAPI 应用、服务、Agent、GraphRAG、Probe、沙箱等 |
| `backend/data/seed/` | 图谱种子 CSV |
| `backend/data/threat_intel/playbooks.json` | 静态威胁剧本数据源 |
| `backend/scripts/` | 校验、导入、GraphRAG 构建、威胁情报挂载等脚本 |
| `frontend/` | Vue 3 前端 |
| `docs/architecture.md` | 架构说明 |
| `docs/usage_guide_midstage.md` | 中期原型分步操作指南 |
| `docs/project_overview_and_tech_route.md` | 项目概览与技术路线 |

---

## 六、常见问题（简要）

| 现象 | 建议 |
|------|------|
| 图谱为空或来自文件而非 Neo4j | 检查 `EXPOSURE_GRAPH_BACKEND` 与 Neo4j 连接；执行 `import_to_neo4j.py`。 |
| GraphRAG 无子图上下文 | 确认 `graph_rag_neo4j_subgraph_enabled` 等配置；问题文本需能匹配到实体 token。 |
| Agent 无法 finish | 需有一次 **成功** 的沙箱执行（允许且退出码为 0）；连续策略拦截有次数上限。 |
| 威胁剧本未挂上 | 确认 JSON 中 `target_node_name` 与图中 `Entity` 的 `label`/`id`/`en_identifier` 子串匹配，且 `target_node_type` 与节点 `type` 一致。 |

---

*文档版本：与仓库当前功能对齐；若 API 或脚本有变更，请以代码与 `README.md` 为准并更新本节。*
