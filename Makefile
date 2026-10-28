# Atajos de desarrollo (Linux/macOS). En Windows ver scripts/demo.ps1.
PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin
DEMO_DB := sqlite:///data/demo.db

.PHONY: help venv install lint format test cov demo-data demo serve docker-up docker-down clean

help:
	@grep -E '^[a-z-]+:' Makefile | cut -d: -f1

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(BIN)/pip install -r requirements-dev.txt
	$(BIN)/pip install -e .

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format:
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

test:
	$(BIN)/pytest

cov:
	$(BIN)/pytest --cov --cov-report=term-missing

demo-data:
	$(BIN)/python scripts/generate_samples.py

demo: demo-data
	rm -f data/demo.db
	LOGAN_DATABASE_URL=$(DEMO_DB) $(BIN)/loganalyzer collect --inventory config/hosts.demo.yaml
	LOGAN_DATABASE_URL=$(DEMO_DB) $(BIN)/loganalyzer analyze --since-hours 240

serve:
	LOGAN_DATABASE_URL=$(DEMO_DB) $(BIN)/loganalyzer serve

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v

clean:
	rm -rf data .pytest_cache .ruff_cache .coverage htmlcov
	find samples -mindepth 1 ! -name .gitkeep -exec rm -rf {} +
