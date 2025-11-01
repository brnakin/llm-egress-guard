.PHONY: install up down logs lint format test regression bench

CONDA_BASE := $(shell conda info --base)
WITH_ENV := . "$(CONDA_BASE)/etc/profile.d/conda.sh" && conda activate "$(HOME)/.conda/envs/LLM Egress Guard"

install:
	$(WITH_ENV) && pip install -e .[dev]

up:
	docker compose up -d --build

logs:
	docker compose logs -f app

down:
	docker compose down

lint:
	$(WITH_ENV) && ruff check app tests && black --check app tests

format:
	$(WITH_ENV) && black app tests

test:
	$(WITH_ENV) && pytest -q

regression:
	$(WITH_ENV) && python tests/regression/runner.py

bench:
	chmod +x scripts/bench.sh && ./scripts/bench.sh
