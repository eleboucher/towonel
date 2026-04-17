.PHONY: build test lint fmt check docker docker-agent docker-node up down e2e release clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	cargo build --release -p towonel-agent -p towonel-node -p towonel-cli

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

e2e:
	docker compose -f docker-compose.e2e.yml down -v
	docker compose -f docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from test-runner
	docker compose -f docker-compose.e2e.yml down -v

release:
	@test -n "$(V)" || (echo "usage: make release V=0.1.0" && exit 1)
	git tag -a "v$(V)" -m "v$(V)"
	@echo "Tagged v$(V). Push with: git push origin v$(V)"

clean:
	cargo clean
	docker compose -f docker-compose.e2e.yml down -v 2>/dev/null || true
