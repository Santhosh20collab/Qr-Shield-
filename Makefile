PY ?= python

.PHONY: help install dev data download prepare train test lint cov run benchmark docker clean

help:
	@echo "QR Shield targets:"
	@echo "  install    runtime dependencies"
	@echo "  dev        runtime + test/lint dependencies"
	@echo "  data       download datasets and build grouped splits"
	@echo "  train      train, calibrate and evaluate the model"
	@echo "  test       run the test suite"
	@echo "  lint       run ruff"
	@echo "  cov        tests with coverage report"
	@echo "  run        start the web app on http://127.0.0.1:8000"
	@echo "  benchmark  measure model latency and QR decode robustness"
	@echo "  docker     build and run with docker compose"

install:
	$(PY) -m pip install -r requirements.txt

dev:
	$(PY) -m pip install -r requirements-dev.txt

download:
	$(PY) scripts/download_data.py

prepare:
	$(PY) scripts/prepare_data.py

data: download prepare

train:
	$(PY) scripts/train_model.py --n-jobs 8

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check qrshield app scripts tests

cov:
	$(PY) -m pytest --cov=qrshield --cov=app --cov-report=term-missing

run:
	$(PY) -m qrshield serve

benchmark:
	$(PY) scripts/benchmark_qr.py
	$(PY) scripts/model_benchmark.py

docker:
	docker compose up --build

clean:
	$(PY) -c "import shutil,pathlib; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
