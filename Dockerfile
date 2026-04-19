# syntax=docker/dockerfile:1.23
ARG ENABLE_SCCACHE=0

FROM rust:1.95-bookworm AS chef
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-chef sccache --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG ENABLE_SCCACHE
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/root/.cache/sccache \
    --mount=type=secret,id=SCCACHE_AWS_ACCESS_KEY_ID,required=false \
    --mount=type=secret,id=SCCACHE_AWS_SECRET_ACCESS_KEY,required=false \
    if [ "$ENABLE_SCCACHE" = "1" ]; then \
        export RUSTC_WRAPPER=sccache \
               SCCACHE_BUCKET=sccache \
               SCCACHE_ENDPOINT=https://s3.erwanleboucher.dev \
               SCCACHE_REGION=us-east-1 \
               SCCACHE_S3_USE_SSL=true \
               AWS_ACCESS_KEY_ID="$(cat /run/secrets/SCCACHE_AWS_ACCESS_KEY_ID)" \
               AWS_SECRET_ACCESS_KEY="$(cat /run/secrets/SCCACHE_AWS_SECRET_ACCESS_KEY)"; \
    fi && \
    cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/root/.cache/sccache \
    --mount=type=secret,id=SCCACHE_AWS_ACCESS_KEY_ID,required=false \
    --mount=type=secret,id=SCCACHE_AWS_SECRET_ACCESS_KEY,required=false \
    if [ "$ENABLE_SCCACHE" = "1" ]; then \
        export RUSTC_WRAPPER=sccache \
               SCCACHE_BUCKET=sccache \
               SCCACHE_ENDPOINT=https://s3.erwanleboucher.dev \
               SCCACHE_REGION=us-east-1 \
               SCCACHE_S3_USE_SSL=true \
               AWS_ACCESS_KEY_ID="$(cat /run/secrets/SCCACHE_AWS_ACCESS_KEY_ID)" \
               AWS_SECRET_ACCESS_KEY="$(cat /run/secrets/SCCACHE_AWS_SECRET_ACCESS_KEY)"; \
    fi && \
    cargo build --release -p towonel-agent -p towonel-node -p towonel-cli && \
    mkdir -p /out && \
    cp target/release/towonel-agent target/release/towonel-node target/release/towonel-cli /out/

FROM debian:bookworm-slim AS runtime-prep
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 nonroot \
    && useradd -u 10001 -g 10001 -M -s /sbin/nologin nonroot \
    && install -d -o 10001 -g 10001 /var/lib/towonel /etc/towonel /data/certs /home/nonroot
COPY --from=builder /out/towonel-agent /usr/local/bin/towonel-agent
COPY --from=builder /out/towonel-node  /usr/local/bin/towonel-node
COPY --from=builder /out/towonel-cli   /usr/local/bin/towonel-cli
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/towonel-node

FROM gcr.io/distroless/cc-debian12
LABEL org.opencontainers.image.title="turbo-tunnel" \
      org.opencontainers.image.source="https://git.erwanleboucher.dev/erwan/turbo-tunnel" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=runtime-prep /etc/passwd /etc/passwd
COPY --from=runtime-prep /etc/group  /etc/group
COPY --from=runtime-prep --chown=10001:10001 /var/lib/towonel /var/lib/towonel
COPY --from=runtime-prep --chown=10001:10001 /etc/towonel     /etc/towonel
COPY --from=runtime-prep --chown=10001:10001 /data/certs      /data/certs
COPY --from=runtime-prep --chown=10001:10001 /home/nonroot    /home/nonroot
COPY --from=runtime-prep /usr/local/bin/towonel-agent /usr/local/bin/towonel-agent
COPY --from=runtime-prep /usr/local/bin/towonel-node  /usr/local/bin/towonel-node
COPY --from=runtime-prep /usr/local/bin/towonel-cli   /usr/local/bin/towonel-cli
WORKDIR /home/nonroot
USER 10001:10001
# Distroless has no shell; probe health ports via K8s liveness/readiness.
