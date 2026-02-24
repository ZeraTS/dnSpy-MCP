.PHONY: build run stop clean test docker-build docker-run docker-stop help

help:
	@echo "Available commands:"
	@echo "  make build          - Install dependencies"
	@echo "  make run            - Run daemon locally"
	@echo "  make test           - Test API endpoints"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-run     - Start Docker container"
	@echo "  make docker-stop    - Stop Docker container"
	@echo "  make clean          - Clean up temporary files"

build:
	pip install -r requirements.txt

run:
	python3 daemon.py

test:
	bash test_api.sh

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
