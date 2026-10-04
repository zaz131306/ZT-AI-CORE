# =============================================================================
# ZT-AI-CORE — fsm-engine (L6). glibc-базис (F-E-08).
# Build context: корень репозитория.
# =============================================================================
FROM rust:1.79-bookworm AS build
WORKDIR /src
COPY submodules/hal-common ./hal-common
COPY submodules/fsm-engine ./fsm-engine
WORKDIR /src/fsm-engine
RUN cargo build --release && cargo test --release --quiet

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 7402 --shell /usr/sbin/nologin ztfsm \
    && mkdir -p /var/lib/zt-fsm /run/zt-core \
    && chown -R ztfsm:ztfsm /var/lib/zt-fsm /run/zt-core
COPY --from=build /src/fsm-engine/target/release/zt-fsm-engine /usr/local/bin/zt-fsm-engine
USER ztfsm
ENTRYPOINT ["/usr/local/bin/zt-fsm-engine"]
CMD ["serve", "--socket", "/run/zt-core/fsm.sock", \
     "--wal", "/var/lib/zt-fsm/wal.log"]
