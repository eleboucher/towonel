# syntax=docker/dockerfile:1.6
FROM rust:1.94-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p turbo-agent -p turbo-node -p turbo-cli && \
    mkdir -p /out && \
    cp target/release/turbo-agent target/release/turbo-node target/release/turbo-cli /out/

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/turbo-agent /usr/local/bin/
COPY --from=builder /out/turbo-node  /usr/local/bin/
COPY --from=builder /out/turbo-cli   /usr/local/bin/
