"""
将静态红队剧本（ThreatVector）确定性挂载到 Neo4j 业务图谱。

- 读取 ``backend/data/threat_intel/playbooks.json``（路径在代码中常量定义）。
- 仅 ``MERGE`` 新节点与 ``VULNERABLE_TO`` 边，**不**清空、不覆盖已有 ``Entity`` / Milvus 数据。

用法（在 ``backend`` 目录下）::

    python scripts/ingest_threat_intel.py
    python scripts/ingest_threat_intel.py --path data/threat_intel/playbooks.json
    python scripts/ingest_threat_intel.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 默认与 ``app.services.threat_intel_playbook_io.PLAYBOOKS_DEFAULT_PATH`` 对齐
DEFAULT_PLAYBOOKS_PATH = ROOT / "data" / "threat_intel" / "playbooks.json"

from app.repositories.graph_repository import Neo4jGraphRepository, get_graph_repository  # noqa: E402
from app.services.threat_intel_playbook_io import (  # noqa: E402
    load_playbook_rows,
    validate_playbook_row,
)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--path",
        type=str,
        default=None,
        help=f"playbooks.json 路径；默认 {DEFAULT_PLAYBOOKS_PATH}",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="只统计可匹配实体数，不写 Neo4j",
    )
    p.add_argument(
        "--print-json",
        action="store_true",
        help="将统计结果以 JSON 打印到 stdout",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    path = Path(args.path) if args.path else DEFAULT_PLAYBOOKS_PATH
    if not path.is_file():
        print(f"Missing playbooks file: {path}", file=sys.stderr)
        return 1

    repo = get_graph_repository()
    if not isinstance(repo, Neo4jGraphRepository):
        print(
            "当前 graph_backend 非 neo4j 或 Neo4j 不可用（已回退文件仓储）。"
            "请设置 EXPOSURE_GRAPH_BACKEND=neo4j 并确保 Neo4j 可连后再运行。",
            file=sys.stderr,
        )
        return 2

    rows = load_playbook_rows(path)
    bad: list[dict[str, str]] = []
    good: list[dict[str, object]] = []
    for i, row in enumerate(rows):
        ok, reason = validate_playbook_row(row)
        if not ok:
            bad.append({"index": str(i), "reason": reason})
        else:
            good.append(row)

    if bad:
        print("Validation failures:", file=sys.stderr)
        print(json.dumps(bad, ensure_ascii=False, indent=2), file=sys.stderr)
        return 3

    stats = repo.ingest_static_threat_playbooks(good, dry_run=bool(args.dry_run))
    stats["playbooks_path"] = str(path.resolve())
    stats["valid_rows"] = len(good)
    if args.print_json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    else:
        print(
            f"Ingest {'(dry-run) ' if args.dry_run else ''}from {path}: "
            f"rows={stats.get('rows')} linked_edges={stats.get('linked_edges')} "
            f"skipped_no_entity={stats.get('skipped_no_entity', 0)}"
        )
        if stats.get("warnings"):
            print("Warnings:", file=sys.stderr)
            for w in stats["warnings"][:50]:
                print(f"  - {w}", file=sys.stderr)
            if len(stats["warnings"]) > 50:
                print(f"  ... and {len(stats['warnings']) - 50} more", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
