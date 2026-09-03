"""Chapter 5 figures and tables from paper/evaluation/results/.

fig5-1   encrypt and decrypt medians per scheme and payload size (log scale)
fig5-2   overhead of CPDPM over raw AES-GCM as a ratio, by payload size
table5-1 the attack matrix as Markdown (paper/figures/table5-1_attack_matrix.md)

Run: python -m paper.evaluation.make_figures
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RESULTS = Path(__file__).resolve().parent / "results"
FIGURES = ROOT / "paper" / "figures"

# Fixed categorical order; validated palette (see paper/analysis/make_figures.py).
COLORS = {
    "aes-gcm": "#2a78d6",
    "fernet": "#eb6834",
    "tink": "#1baf7a",
    "cpdpm-gcm": "#eda100",
    "cpdpm-xchacha": "#e87ba4",
}
LABELS = {
    "aes-gcm": "AES-256-GCM (raw)",
    "fernet": "Fernet",
    "tink": "Tink AES-256-GCM",
    "cpdpm-gcm": "CPDPM, AES-GCM",
    "cpdpm-xchacha": "CPDPM, XChaCha",
}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e6e6e3"
plt.rcParams.update(
    {
        "font.size": 9,
        "axes.edgecolor": INK2,
        "axes.labelcolor": INK,
        "xtick.color": INK2,
        "ytick.color": INK2,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.color": GRID,
        "grid.linewidth": 0.6,
        "axes.axisbelow": True,
        "legend.frameon": False,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
    }
)


def _rows() -> list[dict]:  # type: ignore[type-arg]
    return json.loads((RESULTS / "benchmark.json").read_text())["rows"]


def fig_latency(rows: list[dict]) -> None:  # type: ignore[type-arg]
    sizes = sorted({r["n"] for r in rows})
    schemes = [s for s in COLORS if any(r["scheme"] == s for r in rows)]
    x = np.arange(len(sizes))
    w = 0.8 / len(schemes)
    fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.0), sharey=True)
    for ax, op in zip(axes, ("encrypt", "decrypt"), strict=True):
        for i, s in enumerate(schemes):
            med = [
                next(
                    r["median_us"]
                    for r in rows
                    if r["scheme"] == s and r["op"] == op and r["n"] == n
                )
                for n in sizes
            ]
            ax.bar(
                x + (i - len(schemes) / 2 + 0.5) * w,
                med,
                w,
                color=COLORS[s],
                label=LABELS[s],
                edgecolor="white",
                linewidth=0.8,
            )
        ax.set_yscale("log")
        ax.set_xticks(x, [f"{n} obs" for n in sizes])
        ax.set_title(op.capitalize(), loc="left", color=INK, fontsize=10)
    axes[0].set_ylabel("Median latency (µs, log)")
    axes[0].legend(fontsize=7.5, loc="upper left", ncol=1)
    fig.suptitle(
        "Latency per operation on FHIR Bundle payloads", x=0.01, ha="left", fontsize=10, color=INK
    )
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    for ext in ("pdf", "png"):
        fig.savefig(FIGURES / f"fig5-1_latency.{ext}")
    plt.close(fig)


def fig_overhead(rows: list[dict]) -> None:  # type: ignore[type-arg]
    sizes = sorted({r["n"] for r in rows})
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    for s in ("cpdpm-gcm", "cpdpm-xchacha", "tink", "fernet"):
        pts = []
        for n in sizes:
            enc = next(
                (r for r in rows if r["scheme"] == s and r["op"] == "encrypt" and r["n"] == n), None
            )
            pts.append(enc["ratio_to_aes_gcm"] if enc else np.nan)
        ax.plot(sizes, pts, marker="o", ms=5, lw=2, color=COLORS[s], label=LABELS[s])
        ax.annotate(
            f"{pts[-1]:.1f}×",
            (sizes[-1], pts[-1]),
            textcoords="offset points",
            xytext=(6, {"cpdpm-gcm": 6, "tink": -6}.get(s, 0)),
            va="center",
            fontsize=8,
            color=INK,
        )
    ax.axhline(1.0, color=INK2, lw=0.8, ls="--")
    ax.set_yscale("log")
    ax.set_xscale("log")
    ax.set_xticks(sizes, [f"{n}" for n in sizes])
    ax.set_xlabel("Observations per payload")
    ax.set_ylabel("Encrypt time ÷ raw AES-GCM (log)")
    ax.set_title(
        "Overhead over raw AES-GCM shrinks as payloads grow", loc="left", color=INK, fontsize=10
    )
    ax.legend(fontsize=8)
    for ext in ("pdf", "png"):
        fig.savefig(FIGURES / f"fig5-2_overhead.{ext}")
    plt.close(fig)


def table_attacks() -> None:
    data = json.loads((RESULTS / "record_swap.json").read_text())
    attacks = ["patient_swap", "tenant_move", "field_move", "stale_replay_after_retirement"]
    heads = ["Scheme", "Correct row", "Patient swap", "Tenant move", "Field move", "Stale replay"]
    lines = ["| " + " | ".join(heads) + " |", "|" + "---|" * len(heads)]
    for scheme, cells in data["matrix"].items():
        vals = [cells["control"]] + [cells[a] for a in attacks]
        lines.append("| " + " | ".join([scheme] + vals) + " |")
    fh = data["fhir_layer"]
    lines.append(f"| {fh['scheme']} | accepted | {fh['patient_swap']['outcome']} | – | – | – |")
    (FIGURES / "table5-1_attack_matrix.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    if (RESULTS / "benchmark.json").exists():
        rows = _rows()
        fig_latency(rows)
        fig_overhead(rows)
    if (RESULTS / "record_swap.json").exists():
        table_attacks()
    print(f"wrote chapter 5 outputs to {FIGURES}")


if __name__ == "__main__":
    main()
