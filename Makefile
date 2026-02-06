.PHONY: setup fmt lint test

setup:
	python -m pip install -r requirements.txt

fmt:
	python -m ruff format .

lint:
	python -m ruff check .

test:
	python -m pytest
