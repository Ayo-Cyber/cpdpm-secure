PY ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: setup test coverage lint typecheck analysis evaluation evaluation-fast figures diagrams paper docx all clean

## One-command setup: fresh virtualenv with the package and dev tools.
setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[dev,paper]"

## The gate. A fresh clone must pass this with no other steps.
test:
	$(BIN)/pytest

coverage:
	$(BIN)/pytest --cov --cov-report=term-missing

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

typecheck:
	$(BIN)/mypy

## Chapter 3: every number in the analysis chapter comes from these scripts.
analysis:
	$(BIN)/python -m paper.analysis.pre_transform
	$(BIN)/python -m paper.analysis.fair_benchmark

## Chapter 5: attack matrix and pyperf benchmarks (needs `pip install tink`).
evaluation:
	$(BIN)/python -m paper.evaluation.record_swap
	$(BIN)/python -m paper.evaluation.containment
	$(BIN)/python -m paper.evaluation.benchmark -o paper/evaluation/results/bench_pyperf.json --quiet
	$(BIN)/python -m paper.evaluation.summarize

evaluation-fast:
	$(BIN)/python -m paper.evaluation.record_swap
	$(BIN)/python -m paper.evaluation.containment
	$(BIN)/python -m paper.evaluation.benchmark --fast -o paper/evaluation/results/bench_pyperf.json --quiet
	$(BIN)/python -m paper.evaluation.summarize

## Regenerates every figure and table in paper/figures from raw results.
figures:
	$(BIN)/python -m paper.analysis.make_figures
	$(BIN)/python -m paper.evaluation.make_figures
	$(BIN)/python -m paper.construction.overhead_table

## Diagram PDFs from paper/diagrams/*.svg via svglib (fallback renderer; the committed
## PNG/PDF pairs were rendered in Chromium for exact fonts, see paper/README.md).
diagrams:
	$(BIN)/python -m paper.diagrams.render

## The manuscript. Numbers are regenerated from the pinned results first, so the text
## cannot drift from the evidence. Needs tectonic (brew install tectonic).
paper:
	$(BIN)/python -m paper.manuscript_numbers
	cd manuscript && tectonic -X compile --keep-logs main.tex
	@echo "manuscript/main.pdf"

## Word export of the manuscript via pandoc (brew install pandoc). Figures as PNG,
## numeric citations in Elsevier style; the LaTeX PDF remains the submission artefact.
docx:
	$(BIN)/python -m paper.manuscript_numbers
	$(BIN)/python -m paper.docx_prep
	cd manuscript && pandoc docx.tex --from latex --to docx --citeproc \
	  --bibliography refs.bib --csl elsevier-vancouver.csl \
	  --resource-path=.:figures-png --default-image-extension=png \
	  --metadata link-citations=true -o main.docx
	@echo "manuscript/main.docx"

## Everything the paper needs, from a clean checkout: gate, analysis, evaluation, figures.
all: test analysis evaluation figures

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
