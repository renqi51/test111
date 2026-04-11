"""
最小入库验证：在 data/input 中选体积最小的 .yaml/.yml，默认只处理「第一个文本块」
（与正式 chunk 参数一致），写入 Neo4j 并打印合并前后节点/边数量。

用法（在 backend 目录）:
  python scripts/verify_minimal_yaml_import.py
  python scripts/verify_minimal_yaml_import.py --dry-run
  python scripts/verify_minimal_yaml_import.py --full-file   # 整文件所有 chunk（更贵）
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import settings  # noqa: E402
from app.repositories.graph_repository import get_graph_repository  # noqa: E402
from app.services.kg_builder_service import get_kg_builder_service  # noqa: E402
from app.utils.file_parser import chunk_text, read_rule_context_multi  # noqa: E402


def _pick_smallest_yaml(input_dir: Path) -> Path:
    cands = [
        p
        for p in input_dir.iterdir()
        if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}
    ]
    if not cands:
        raise SystemExit(f"No .yaml/.yml under {input_dir}")
    cands.sort(key=lambda p: (p.stat().st_size, p.name))
    return cands[0]


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true", help="只跑抽取，不写 Neo4j")
    p.add_argument(
        "--full-file",
        action="store_true",
        help="处理该 yaml 的全部 chunk（费用高）；默认仅第一个 chunk",
    )
    return p.parse_args()


async def _run(*, dry_run: bool, full_file: bool) -> int:
    if not settings.llm_enabled:
        print("EXPOSURE_LLM_* 未配置完整，llm_enabled=false，跳过验证。")
        return 2

    input_dir = Path(settings.kg_input_dir)
    yaml_path = _pick_smallest_yaml(input_dir)
    print(f"[verify] smallest yaml: {yaml_path.name} ({yaml_path.stat().st_size} bytes)")

    text = yaml_path.read_text(encoding="utf-8").strip()
    if not text:
        print("[verify] empty file")
        return 1

    rule_context = read_rule_context_multi(Path(settings.kg_rule_dir))
    print(f"[verify] rule_context_chars={len(rule_context)}")

    chunks = chunk_text(
        text,
        chunk_size=settings.kg_chunk_size,
        chunk_overlap=settings.kg_chunk_overlap,
    )
    if not chunks:
        print("[verify] no chunks after chunk_text")
        return 1

    if full_file:
        use_chunks = chunks
        print(f"[verify] mode=full_file chunks_total={len(use_chunks)}")
    else:
        use_chunks = chunks[:1]
        print(f"[verify] mode=first_chunk_only (of {len(chunks)} total chunks)")

    svc = get_kg_builder_service()
    repo = get_graph_repository()
    before = repo.get_graph()
    n0, e0 = len(before["nodes"]), len(before["edges"])
    print(f"[verify] graph before: nodes={n0} edges={e0} backend={settings.graph_backend}")

    file_nodes, file_edges, ok_c, bad_c = await svc._process_chunks_concurrently(  # noqa: SLF001
        source_file=yaml_path.name,
        chunks=use_chunks,
        rule_context=rule_context,
    )
    print(f"[verify] extract ok_chunks={ok_c} empty_or_failed_chunks={bad_c} raw_nodes={len(file_nodes)} raw_edges={len(file_edges)}")

    merged_nodes, merged_edges = svc._normalize_and_merge(file_nodes, file_edges)  # noqa: SLF001
    nodes_payload = [svc._node_to_graph_payload(n) for n in merged_nodes.values()]  # noqa: SLF001
    edges_payload = [svc._edge_to_graph_payload(e) for e in merged_edges.values()]  # noqa: SLF001
    print(f"[verify] merged nodes={len(nodes_payload)} edges={len(edges_payload)}")

    if dry_run:
        print("[verify] dry-run: skip merge_nodes_edges")
        return 0

    repo.merge_nodes_edges(nodes_payload, edges_payload)
    after = repo.get_graph()
    n1, e1 = len(after["nodes"]), len(after["edges"])
    print(f"[verify] graph after:  nodes={n1} edges={e1} (delta nodes +{n1 - n0}, edges +{e1 - e0})")
    tv = sum(1 for n in after["nodes"] if str(n.get("type", "")) == "ThreatVector")
    vul = sum(1 for n in after["nodes"] if str(n.get("type", "")) == "Vulnerability")
    vedges = sum(1 for e in after["edges"] if str(e.get("interaction", "")) in {"vulnerable_to", "enables_vector"})
    print(f"[verify] threat graph counts: ThreatVector={tv} Vulnerability={vul} threat_edges={vedges}")
    print("[verify] OK: merge_nodes_edges completed")
    return 0


def main() -> None:
    args = _parse_args()
    raise SystemExit(asyncio.run(_run(dry_run=args.dry_run, full_file=args.full_file)))


if __name__ == "__main__":
    main()
