.PHONY: install install-dev test lint format typecheck check run-example clean

VENV_PYTHON ?= python

install:
	$(VENV_PYTHON) -m pip install -e .

install-dev:
	$(VENV_PYTHON) -m pip install -e ".[dev]"

test:
	$(VENV_PYTHON) -m pytest

lint:
	$(VENV_PYTHON) -m ruff check src test/llm_redteam test/llm_firewall examples

format:
	$(VENV_PYTHON) -m ruff format src test/llm_redteam test/llm_firewall examples
	$(VENV_PYTHON) -m ruff check --fix src test/llm_redteam test/llm_firewall examples

typecheck:
	$(VENV_PYTHON) -m mypy

check: lint typecheck test

run-example:
	$(VENV_PYTHON) examples/run_example_campaign.py

run-example-cli:
	$(VENV_PYTHON) -m llm_redteam_firewall.cli.main run --config configs/example_campaign.yaml

clean:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} \;
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
