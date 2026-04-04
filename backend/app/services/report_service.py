"""Markdown / Mermaid / demo summary generation."""
from __future__ import annotations

from datetime import datetime, timezone

from app.services.graph_engine import compute_stats, validate_graph
from app.utils.storage import load_runtime_graph


def build_validation_markdown() -> str:
    g = load_runtime_graph()
    nodes, edges = g["nodes"], g["edges"]
    vr = validate_graph(nodes, edges)
    stats = compute_stats(nodes, edges)
    lines = [
        "# 图谱校验报告",
        "",
        f"_生成时间（UTC）：{datetime.now(timezone.utc).isoformat()}_",
        "",
        "## 摘要",
        "",
        f"- 节点数：**{stats['node_count']}**",
        f"- 边数：**{stats['edge_count']}**",
        f"- 引用完整性：**{'PASS' if vr.ok else 'FAIL'}**",
        "",
        "## 节点类型分布",
        "",
    ]
    for k, v in sorted(stats["by_node_type"].items()):
        lines.append(f"- `{k}`: {v}")
    lines.extend(["", "## 关系类型分布", ""])
    for k, v in sorted(stats["by_edge_type"].items()):
        lines.append(f"- `{k}`: {v}")
    lines.extend(["", "## 高度数节点（Top 10）", ""])
    for item in stats["top_degree_nodes"]:
        lines.append(f"- `{item['id']}` — degree {item['degree']}")
    lines.extend(["", "## 孤立节点", ""])
    lines.append(", ".join(f"`{x}`" for x in vr.orphan_nodes) or "_无_")
    lines.extend(["", "## 悬空边（端点缺失）", ""])
    if not vr.dangling_edges:
        lines.append("_无_")
    else:
        for d in vr.dangling_edges:
            lines.append(f"- {d}")
    lines.extend(["", "## 未被 documented_in 引用的标准文档节点", ""])
    lines.append(", ".join(f"`{x}`" for x in vr.unreferenced_standard_docs) or "_无_")
    lines.extend(["", "## 尚未关联缓解措施的风险假设", ""])
    lines.append(", ".join(f"`{x}`" for x in vr.risks_without_mitigation) or "_无_")
    lines.extend(["", "## 原始 issues", ""])
    for i in vr.issues:
        lines.append(f"- **{i.code}**: {i.detail}")
    return "\n".join(lines) + "\n"


def build_mermaid() -> str:
    g = load_runtime_graph()
    lines = ["flowchart LR"]
    for n in g["nodes"]:
        safe = n["id"].replace("-", "_")
        label = n.get("label", n["id"]).replace('"', "'")
        lines.append(f'  {safe}["{label}"]')
    for e in g["edges"]:
        s = e["source"].replace("-", "_")
        t = e["target"].replace("-", "_")
        lines.append(f"  {s} -->|{e['interaction']}| {t}")
    return "\n".join(lines) + "\n"


def build_demo_summary_md() -> str:
    g = load_runtime_graph()
    nodes, edges = g["nodes"], g["edges"]
    stats = compute_stats(nodes, edges)
    vr = validate_graph(nodes, edges)
    lines = [
        "# Demo 摘要",
        "",
        "## 项目简介",
        "",
        "本原型演示 **大模型辅助思路下的** 3GPP/GSMA 开放服务暴露面发现流程：",
        "知识图谱承载对象与证据、规则抽取产生候选、候选暴露面生成器输出可验证条目，并配套校验与报告导出。",
        "",
        "## 当前规模",
        "",
        f"- 节点：**{len(nodes)}**",
        f"- 边：**{len(edges)}**",
        f"- 校验状态：**{'PASS' if vr.ok else '需关注'}**",
        "",
        "## 核心研究对象",
        "",
        "- VoWiFi / IMS / RCS / Open Gateway",
        "- ePDG、N3IWF、IMS CSCF 家族",
        "- SIP、DNS、IKEv2/IPsec、HTTPS/REST",
        "- FQDN 命名模式与标准文档节点",
        "",
        "## 工具能力（WorkProduct）",
        "",
        "- 标准文本规则抽取器（可替换为 LLM Provider）",
        "- 图谱校验与 Markdown 报告",
        "- 候选暴露面生成与 CSV 导出",
        "- Mermaid 拓扑导出",
        "",
        "## 风险假设（示例）",
        "",
        "- 暴露式 FQDN 与边界服务发现链带来的资产可见性",
        "- 开放 API 文档与身份同意管理配置面",
        "",
        "## 实验验证状态",
        "",
        "详见前端「实验验证」面板（mock 任务，不含真实扫描）。",
        "",
    ]
    return "\n".join(lines) + "\n"
