"""
红队威胁情报剧本（静态 JSON）的读取与校验。

与 LLM 抽取的 3GPP 业务图谱解耦：本模块只做确定性 IO，不写 Milvus、不覆盖向量数据。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

# 默认剧本路径：相对 backend 根目录（与 scripts 约定一致）
PLAYBOOKS_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "data" / "threat_intel" / "playbooks.json"

_REQUIRED_KEYS = frozenset(
    {
        "target_node_type",
        "target_node_name",
        "threat_name",
        "vulnerability_type",
        "description",
        "payload_template",
    }
)


def iter_playbook_objects(raw: Any) -> Iterator[dict[str, Any]]:
    """
    将 playbooks.json 顶层结构展平为若干 dict。

    为什么需要展平：
    - 当前仓库中的 ``playbooks.json`` 允许「顶层对象 + 嵌套子数组」混排，合法 JSON 但非统一列表；
      导入脚本必须容错，避免人工合并文件时出错导致整条流水线失败。
    """
    if isinstance(raw, dict):
        yield raw
        return
    if not isinstance(raw, list):
        return
    for item in raw:
        if isinstance(item, dict):
            yield item
        elif isinstance(item, list):
            for sub in item:
                if isinstance(sub, dict):
                    yield sub


def load_playbook_rows(path: Path | None = None) -> list[dict[str, Any]]:
    """从 JSON 文件加载并展平所有剧本行。"""
    p = path or PLAYBOOKS_DEFAULT_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    return [dict(x) for x in iter_playbook_objects(data)]


def validate_playbook_row(row: dict[str, Any]) -> tuple[bool, str]:
    """校验单行字段齐全且为字符串。"""
    missing = _REQUIRED_KEYS - row.keys()
    if missing:
        return False, f"missing_keys:{sorted(missing)}"
    for k in _REQUIRED_KEYS:
        v = row.get(k)
        if not isinstance(v, str) or not str(v).strip():
            return False, f"invalid_field:{k}"
    return True, "ok"
