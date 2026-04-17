# syntax=docker/dockerfile:1.23
FROM rust:1.95-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p towonel-agent -p towonel-node -p towonel-cli && \
    mkdir -p /out && \
    cp target/release/towonel-agent target/release/towonel-node target/release/towonel-cli /out/

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/towonel-agent /usr/local/bin/
COPY --from=builder /out/towonel-node  /usr/local/bin/
COPY --from=builder /out/towonel-cli   /usr/local/bin/
