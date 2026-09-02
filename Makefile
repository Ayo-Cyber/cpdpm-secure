PY ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: setup test lint typecheck legacy-test legacy-setup figures clean

## One-command setup: fresh virtualenv with the package and dev tools.
setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[dev,paper]"

## The gate. A fresh clone must pass this with no other steps.
test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

typecheck:
	$(BIN)/mypy

## Legacy v1 is frozen. Its suite has two known failures (context-key
## non-determinism) that are evidence for the analysis chapter; do not fix them.
legacy-setup:
	$(BIN)/pip install -q -r legacy/requirements.txt

legacy-test:
	$(BIN)/pytest legacy/tests/test_cpdpm_comprehensive.py -q -p no:cacheprovider || true

## Regenerates every figure in paper/figures from raw results (wired in week 6).
figures:
	@echo "paper/figures: no experiments yet (see docs/ROADMAP.md, week 6-8)"

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
