"""CLI: write Mermaid for current runtime graph to stdout or file."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.report_service import build_mermaid  # noqa: E402
from app.utils.storage import init_runtime_from_seed_if_missing  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=Path, help="Write to file instead of stdout")
    args = parser.parse_args()
    init_runtime_from_seed_if_missing()
    text = build_mermaid()
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
