.PHONY: build run run-prod test test-modules docker-build docker-run docker-stop clean cli help

help:
	@echo "Available commands:"
	@echo "  make build          - Install dependencies"
	@echo "  make run            - Run basic daemon"
	@echo "  make run-prod       - Run production daemon (caching, metrics, etc)"
	@echo "  make test           - Test API endpoints"
	@echo "  make test-modules   - Test individual modules"
	@echo "  make cli            - Run CLI tool"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-run     - Start Docker container"
	@echo "  make docker-stop    - Stop Docker container"
	@echo "  make clean          - Clean up temporary files"

build:
	pip install -r requirements.txt

run:
	python3 daemon.py

run-prod:
	python3 daemon_production.py

test:
	bash test_api.sh

test-modules:
	python3 test_modules.py

cli:
	python3 cli.py --help

docker-build:
	docker build -t dnspy-mcp:latest .

docker-run:
	docker-compose up

docker-stop:
	docker-compose down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf build dist *.egg-info
