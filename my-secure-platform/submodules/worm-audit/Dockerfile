# =============================================================================
# ZT-AI-CORE — worm-audit (L7). glibc-базис обязателен (F-E-08).
# Build context: корень репозитория (path-зависимость на hal-common).
# =============================================================================
FROM rust:1.79-bookworm AS build
WORKDIR /src
COPY submodules/hal-common ./hal-common
COPY submodules/worm-audit ./worm-audit
WORKDIR /src/worm-audit
RUN cargo build --release && cargo test --release --quiet

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 7401 --shell /usr/sbin/nologin ztworm \
    && mkdir -p /var/worm /run/zt-core /etc/zt-core/keys \
    && chown -R ztworm:ztworm /var/worm /run/zt-core
COPY --from=build /src/worm-audit/target/release/zt-worm-audit /usr/local/bin/zt-worm-audit
USER ztworm
# Zero-trust гигиена: no-new-privileges задаётся в compose (security_opt)
ENTRYPOINT ["/usr/local/bin/zt-worm-audit"]
CMD ["serve", "--socket", "/run/zt-core/audit.sock", \
     "--chain", "/var/worm/audit-chain.jsonl", \
     "--checkpoints", "/var/worm/checkpoints.jsonl", \
     "--anchor-dir", "/var/worm/anchors"]
