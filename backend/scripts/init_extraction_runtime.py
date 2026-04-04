from __future__ import annotations

from pathlib import Path
import sys

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import settings  # noqa: E402
from app.services.trace_service import ensure_extraction_runtime_dirs  # noqa: E402


def main() -> None:
    ensure_extraction_runtime_dirs()
    override_path = Path(settings.extraction_prompt_override_path)
    if not override_path.exists():
        override_path.parent.mkdir(parents=True, exist_ok=True)
        override_path.write_text(
            '{\n'
            '  "prompts": {},\n'
            '  "examples": {\n'
            '    "judge_scoring": {\n'
            '      "version": "v_override_1",\n'
            '      "template": "replace with your enterprise judge prompt"\n'
            "    }\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        print(f"created prompt override template: {override_path}")
    print("extraction runtime directories initialized")


if __name__ == "__main__":
    main()

