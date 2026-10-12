"""Prepare a pandoc-friendly copy of the manuscript sections for the Word export.

Pandoc's LaTeX reader handles the manuscript well except for a few constructs
that exist only for the PDF layout. This script copies ``manuscript/sections``
to ``manuscript/build-docx/sections`` with those rewritten:

* ``sidewaystable`` becomes ``table`` (Word has no rotated float; the table
  is set full width and Word wraps the cells).
* the ragged-right column type ``R{..}`` becomes plain ``p{..}``.
* ``align*`` blocks become one display equation per line, which pandoc can
  convert to Word's native equation format; ``aligned`` cannot.
* ``\\setlength{\\tabcolsep}`` lines and ``\\\\[len]`` row spacing are dropped.
* group-header rows written with ``\\multicolumn`` become plain rows with the
  heading in the first cell, which pandoc's table reader accepts.

Run: python -m paper.docx_prep
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "manuscript" / "sections"
DST = ROOT / "manuscript" / "build-docx" / "sections"

ALIGN = re.compile(r"\\begin\{align\*\}(.*?)\\end\{align\*\}", re.S)
ROWSPACE = re.compile(r"\\\\\[[0-9.]+pt\]")
BR = r"(?:[^{}]|\{[^{}]*\})*"  # one level of nested braces
MULTICOL = re.compile(r"\\multicolumn\{(\d+)\}\{" + BR + r"\}\{(" + BR + r")\}\s*\\\\")
TABCOLSEP = re.compile(r"^\\setlength\{\\tabcolsep\}\{[^}]*\}\n", re.M)
RAGGED = re.compile(r"R\{([0-9.]+cm)\}")


def _split_align(m: re.Match[str]) -> str:
    lines = [ln.strip() for ln in m.group(1).split("\\\\") if ln.strip()]
    return "\n".join("\\[ " + ln.replace("&", "") + " \\]" for ln in lines)


def _flatten_multicol(m: re.Match[str]) -> str:
    ncols = int(m.group(1))
    return m.group(2) + " &" * (ncols - 1) + " \\\\"


def convert(text: str) -> str:
    text = text.replace("\\input{sections/", "\\input{build-docx/sections/")
    text = text.replace("\\begin{sidewaystable}[p]", "\\begin{table}[h]")
    text = text.replace("\\begin{sidewaystable}", "\\begin{table}")
    text = text.replace("\\end{sidewaystable}", "\\end{table}")
    text = RAGGED.sub(r"p{\1}", text)
    text = TABCOLSEP.sub("", text)
    text = ALIGN.sub(_split_align, text)
    text = ROWSPACE.sub(r"\\\\", text)
    text = MULTICOL.sub(_flatten_multicol, text)
    return text


def main() -> None:
    if DST.exists():
        shutil.rmtree(DST)
    DST.mkdir(parents=True)
    for tex in sorted(SRC.glob("*.tex")):
        (DST / tex.name).write_text(convert(tex.read_text()))
    print(f"prepared {len(list(DST.glob('*.tex')))} sections in {DST.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
