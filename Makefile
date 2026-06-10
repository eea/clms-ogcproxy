.PHONY: start
start:
	uvicorn ogcproxy:app --host 0.0.0.0 --port 8000 --reload

docker-release: build-docker publish
	@echo "Building"

.PHONY: build-docker
build-docker:
	docker build . --no-cache -t eeacms/clms-ogcproxy:latest

.PHONY: publish
publish:
	docker push eeacms/clms-ogcproxy:latest
