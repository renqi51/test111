"""Reset runtime graph_state.json from seed CSV files."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.utils.storage import reset_runtime_from_seed  # noqa: E402


def main() -> int:
    reset_runtime_from_seed()
    print("Runtime graph reset from seed CSV.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
