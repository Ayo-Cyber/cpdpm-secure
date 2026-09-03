# Reproduces every number and figure in the paper from a clean container.
#   docker build -t cpdpm-paper .
#   docker run --rm -v "$PWD/paper/figures:/work/paper/figures" cpdpm-paper
FROM python:3.12-slim
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends make && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY pyproject.toml README.md LICENSE Makefile ./
COPY cpdpm ./cpdpm
COPY tests ./tests
COPY paper ./paper
COPY data ./data
RUN python -m venv .venv && .venv/bin/pip install -q --upgrade pip \
 && .venv/bin/pip install -q -e ".[dev,paper]"
CMD ["make", "all"]
