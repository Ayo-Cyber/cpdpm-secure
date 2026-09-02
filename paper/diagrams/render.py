"""Render the hand-authored SVG diagrams in this folder to PDF in paper/figures.

SVG is the source of truth; edit the .svg files, then run this. PDF rendering
uses svglib + reportlab (pure Python, no system libraries). PNG previews are
made with a browser (see README) because a faithful pure-Python rasteriser is
not available everywhere.

Run: python -m paper.diagrams.render
"""

from __future__ import annotations

from pathlib import Path

from reportlab.graphics import renderPDF
from svglib.svglib import svg2rlg

HERE = Path(__file__).resolve().parent
FIGURES = HERE.parent / "figures"


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    for svg in sorted(HERE.glob("*.svg")):
        drawing = svg2rlg(str(svg))
        if drawing is None:
            raise SystemExit(f"could not parse {svg.name}")
        out = FIGURES / (svg.stem + ".pdf")
        renderPDF.drawToFile(drawing, str(out))
        print(f"wrote {out.relative_to(HERE.parent.parent)}")


if __name__ == "__main__":
    main()
