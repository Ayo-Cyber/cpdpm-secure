"""Chapter 3 figures, generated from paper/analysis/results/*.json.

fig3-1  v1 vs transform-free baseline, encrypt and decrypt, KDF counted equally.
fig3-2  Where the time goes: PBKDF2, AES-CBC+HMAC, the Python transform loop.

Run: python -m paper.analysis.make_figures
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from paper.analysis._legacy import FIGURES, read_result  # noqa: E402

# Categorical slots, fixed order, validated for CVD separation on a white surface.
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e6e6e3"

plt.rcParams.update(
    {
        "font.family": "sans-serif",
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


def _size_label(nbytes: int) -> str:
    return f"{nbytes // 1024} KB" if nbytes < 1024 * 1024 else f"{nbytes // (1024 * 1024)} MB"


def _iqr(d: dict) -> tuple[float, float]:
    return d["median_ms"] - d["p25_ms"], d["p75_ms"] - d["median_ms"]


def fig_ratio(res: dict) -> None:
    sizes = res["sizes_bytes"]
    x = np.arange(len(sizes))
    w = 0.38
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
    for ax, op in zip(axes, ("encrypt", "decrypt"), strict=True):
        v1 = [res["per_size"][str(s)][f"v1_{op}"] for s in sizes]
        base = [res["per_size"][str(s)][f"baseline_{op}"] for s in sizes]
        for off, series, color, label in (
            (-w / 2, v1, BLUE, "CPDPM v1 (with transform)"),
            (w / 2, base, ORANGE, "Same pipeline, transform removed"),
        ):
            med = [d["median_ms"] for d in series]
            err = np.array([_iqr(d) for d in series]).T
            ax.bar(x + off, med, w, color=color, label=label, edgecolor="white", linewidth=1)
            ax.errorbar(x + off, med, yerr=err, fmt="none", ecolor=INK2, elinewidth=0.8, capsize=2)
        for i, s in enumerate(sizes):
            r = res["per_size"][str(s)][f"ratio_v1_over_baseline_{op}"]
            top = max(v1[i]["p75_ms"], base[i]["p75_ms"])
            ax.text(x[i], top * 1.04, f"{r:.2f}×", ha="center", va="bottom", color=INK, fontsize=8)
        ax.set_xticks(x, [_size_label(s) for s in sizes])
        ax.set_title(op.capitalize(), loc="left", color=INK, fontsize=10)
    axes[0].set_ylabel("Time (ms), median with IQR")
    axes[0].legend(loc="upper left", fontsize=8)
    fig.suptitle(
        "KDF counted on both sides: the transform is free at record sizes, costly at file sizes",
        x=0.01,
        ha="left",
        fontsize=10,
        color=INK,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    for ext in ("pdf", "png"):
        fig.savefig(FIGURES / f"fig3-1_v1_vs_baseline.{ext}")
    plt.close(fig)


def fig_decomposition(res: dict) -> None:
    sizes = res["sizes_bytes"]
    x = np.arange(len(sizes))
    parts = [
        ("component_pbkdf2", "PBKDF2 (100k iterations)", BLUE),
        ("component_aes_cbc_hmac_encrypt", "AES-256-CBC + HMAC", ORANGE),
        ("component_transform_loop", "Transform loop (pure Python)", AQUA),
    ]
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    bottom = np.zeros(len(sizes))
    for key, label, color in parts:
        vals = np.array([res["per_size"][str(s)][key]["median_ms"] for s in sizes])
        ax.bar(
            x, vals, 0.55, bottom=bottom, color=color, label=label, edgecolor="white", linewidth=1
        )
        bottom += vals
    total = [res["per_size"][str(s)]["v1_encrypt"]["median_ms"] for s in sizes]
    ax.scatter(x, total, marker="_", s=260, color=INK, zorder=3, label="Measured v1 encrypt")
    ax.set_xticks(x, [_size_label(s) for s in sizes])
    ax.set_ylabel("Time (ms), medians")
    ax.set_title("Where a v1 encryption spends its time", loc="left", color=INK, fontsize=10)
    ax.legend(fontsize=8, loc="upper left")
    for ext in ("pdf", "png"):
        fig.savefig(FIGURES / f"fig3-2_v1_time_decomposition.{ext}")
    plt.close(fig)


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    res = read_result("fair_benchmark")
    fig_ratio(res)
    fig_decomposition(res)
    print(f"wrote figures to {FIGURES}")


if __name__ == "__main__":
    main()
