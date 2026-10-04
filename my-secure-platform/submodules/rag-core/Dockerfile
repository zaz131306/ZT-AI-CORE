# =============================================================================
# ZT-AI-CORE — rag-core (L8/D8). Python 3.11 на glibc (F-E-08: не musl!).
#
# ВНИМАНИЕ: в ПРОДАКШЕНЕ D8 запускается на хосте через bwrap+SECCOMP+eBPF
# (submodules/t8-sandbox/bwrap/run.sh). Этот образ — dev/integration-контур
# (docker-compose): rag_core.server на UDS без песочницы L5.
# =============================================================================
FROM python:3.11-slim-bookworm

RUN useradd --system --uid 7404 --shell /usr/sbin/nologin ztrag \
    && mkdir -p /var/rag /run/zt-core /etc/zt-core/keys \
    && chown -R ztrag:ztrag /var/rag /run/zt-core

WORKDIR /opt/zt/rag-core
COPY submodules/rag-core/rag_core ./rag_core

# Канонический хэш (BLAKE3); тяжёлые ML-зависимости (torch/sentence-transformers/
# chromadb) в dev-образ НЕ входят — в prod они eagerly-грузятся bootstrap'ом.
RUN pip install --no-cache-dir blake3==0.4.3 || \
    echo "WARN: blake3 недоступен — используется blake2b fallback"

# Анти-lazy env-флаги F-E-07 (дублируют run.sh для контейнерного контура)
ENV PYTHONDONTWRITEBYTECODE=1 \
    GRPC_DISABLE_DYNAMIC_PLUGINS=1 \
    TORCH_DISABLE_DYNAMIC_JIT=1 \
    PYTHONUNBUFFERED=1
USER ztrag
ENTRYPOINT ["python3", "-m", "rag_core.server"]
CMD ["--socket", "/run/zt-core/rag.sock", "--kb", "/var/rag/kb"]
