"""Turn the pyperf JSON into paper/evaluation/results/benchmark.json.

Per (scheme, op, n): median and mean-with-stdev in microseconds, plus the ratio
of each scheme to aes-gcm at the same (op, n).

Run: python -m paper.evaluation.summarize
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pyperf

RESULTS = Path(__file__).resolve().parent / "results"
IN = RESULTS / "bench_pyperf.json"
_NAME = re.compile(
    r"^(?P<scheme>[^/]+)/(?P<op>encrypt|decrypt)/n=(?P<n>\d+)(?:/bytes=(?P<bytes>\d+))?"
)


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else IN
    suite = pyperf.BenchmarkSuite.load(str(src))
    rows: list[dict[str, Any]] = []
    for bench in suite.get_benchmarks():
        m = _NAME.match(bench.get_name())
        if not m:
            continue
        rows.append(
            {
                "scheme": m["scheme"],
                "op": m["op"],
                "n": int(m["n"]),
                "bytes": int(m["bytes"]) if m["bytes"] else None,
                "median_us": bench.median() * 1e6,
                "mean_us": bench.mean() * 1e6,
                "stdev_us": bench.stdev() * 1e6,
                "values": bench.get_nvalue(),
            }
        )
    floor = {(r["op"], r["n"]): r["median_us"] for r in rows if r["scheme"] == "aes-gcm"}
    for r in rows:
        base = floor.get((r["op"], r["n"]))
        r["ratio_to_aes_gcm"] = r["median_us"] / base if base else None
    meta = suite.get_metadata()
    out = {
        "_meta": {
            "python": meta.get("python_version"),
            "cpu": meta.get("cpu_model_name"),
            "platform": meta.get("platform"),
            "pyperf": meta.get("perf_version"),
            "source": src.name,
            "fast_mode": "--fast" in " ".join(meta.get("command_line", []))
            if isinstance(meta.get("command_line"), list)
            else None,
        },
        "rows": sorted(rows, key=lambda r: (r["n"], r["op"], r["scheme"])),
    }
    import json

    (RESULTS / "benchmark.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"{'n':>5} {'op':8} {'scheme':16} {'median us':>11} {'x aes-gcm':>10}")
    for r in out["rows"]:
        ratio = f"{r['ratio_to_aes_gcm']:.2f}" if r["ratio_to_aes_gcm"] else "-"
        print(f"{r['n']:>5} {r['op']:8} {r['scheme']:16} {r['median_us']:>11.1f} {ratio:>10}")


if __name__ == "__main__":
    main()
