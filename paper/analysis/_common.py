"""Shared helpers for the chapter 3 analysis scripts.

Results are written as JSON to ``paper/analysis/results/`` so that every number
in the chapter is traceable to a script run.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RESULTS = Path(__file__).resolve().parent / "results"
FIGURES = ROOT / "paper" / "figures"


def write_result(name: str, data: dict[str, Any], results_dir: Path = RESULTS) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    out = results_dir / f"{name}.json"
    payload = {
        "_meta": {
            "script": name,
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "system": platform.system(),
        },
        **data,
    }
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out.relative_to(ROOT)}")
    return out


def read_result(name: str) -> dict[str, Any]:
    return json.loads((RESULTS / f"{name}.json").read_text())
