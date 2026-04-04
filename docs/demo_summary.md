# Demo 摘要（静态说明）

运行时可从 API 获取最新统计：`GET /api/demo/summary`（JSON 内嵌 Markdown）或 `GET /api/reports/demo_summary_md`。

本原型用于实验室展示 **「evidence-grounded + human-in-the-loop」3GPP/GSMA 开放服务暴露面发现与验证工作流**：

1. **知识图谱**：统一承载服务、网元、协议、FQDN 模式、标准文档、风险假设与工具产物。
2. **Extraction Pipeline**：共享证据包 + Worker A/B + Judge + 可选 Repair + staging graph。
3. **候选暴露面**：按 MCC/MNC 与服务类型生成可解释的候选 FQDN 与协议栈组合。
4. **人工确认入图**：staging graph 中确认节点/边后再 merge 到主图。
5. **校验与导出**：一致性检查、Markdown 报告、Mermaid、CSV。

**合规声明**：实验验证页为 mock 任务列表；工具不进行未授权真实扫描。
