FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release

FROM node:22-bookworm-slim AS webui-builder

WORKDIR /webui
COPY webui/package.json webui/package-lock.json* ./
RUN npm install --legacy-peer-deps
COPY webui/ .
RUN npm run build

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/kiro-tools /app/kiro-tools
COPY --from=webui-builder /webui/dist /app/dist

ENV KIRO_DIST_PATH=/app/dist
ENV KIRO_BIND_LOCAL_ONLY=false

EXPOSE 8045

ENTRYPOINT ["/app/kiro-tools"]
