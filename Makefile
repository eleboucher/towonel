.PHONY: build test lint fmt check docker docker-agent docker-node up down e2e release clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	cargo build --release -p towonel-agent -p towonel-node

test:
	cargo test --all-targets

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --check

check: fmt lint test

docker:
	docker build -t towonel:$(VERSION) .

docker-agent:
	docker build -f Dockerfile.agent -t towonel-agent:$(VERSION) .

docker-node:
	docker build -f Dockerfile.node -t towonel-node:$(VERSION) .

up:
	docker compose up --build -d

down:
	docker compose down

# NB: run detached and `docker wait` on the runner instead of
# --abort-on-container-exit; the route_recovery case restarts the hub, which
# would otherwise trip the abort and kill the runner mid-test.
e2e:
	./tests/e2e/fixtures/make-fixtures.sh
	docker compose --env-file .env.e2e -f docker-compose.e2e.yml down -v
	docker compose --env-file .env.e2e -f docker-compose.e2e.yml up --build --detach
	@code=$$(docker wait towonel-e2e-runner); \
		docker compose --env-file .env.e2e -f docker-compose.e2e.yml logs --no-color test-runner; \
		echo "test-runner exit code: $$code"; \
		docker compose --env-file .env.e2e -f docker-compose.e2e.yml down -v; \
		exit $$code

release:
	@test -n "$(V)" || (echo "usage: make release V=0.1.0" && exit 1)
	git tag -a "v$(V)" -m "v$(V)"
	@echo "Tagged v$(V). Push with: git push origin v$(V)"

clean:
	cargo clean
	docker compose --env-file .env.e2e -f docker-compose.e2e.yml down -v 2>/dev/null || true
