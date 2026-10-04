# =============================================================================
# ZT-AI-CORE — llm-gateway (L4). Python 3.11 на glibc (bookworm), stdlib-only
# рантайм; blake3 — опциональное ускорение канонического хэша egress-лога.
# =============================================================================
FROM python:3.11-slim-bookworm

RUN useradd --system --uid 7403 --shell /usr/sbin/nologin ztgateway \
    && mkdir -p /var/log/zt-core /run/zt-core /etc/zt-core/keys \
    && chown -R ztgateway:ztgateway /var/log/zt-core /run/zt-core

WORKDIR /opt/zt/llm-gateway
COPY submodules/llm-gateway/llm_gateway ./llm_gateway

# blake3 — канонический хэш (Приложение Б); без него — blake2b fallback
RUN pip install --no-cache-dir blake3==0.4.3 || \
    echo "WARN: blake3 недоступен — egress-лог использует blake2b fallback"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER ztgateway
EXPOSE 8443
ENTRYPOINT ["python3", "-m", "llm_gateway.main"]
CMD ["--listen", "0.0.0.0", "--port", "8443"]
