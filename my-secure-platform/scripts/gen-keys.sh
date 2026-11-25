#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — генерация ключей и сертификатов (scripts/gen-keys.sh)
#
# ВАЖНО (F-H-03): в prod приватные ключи Ed25519 (подпись артефактов/WORM)
# генерируются ВНУТРИ HSM/TPM и никогда не экспортируются. Данный скрипт —
# стендовый эмитент для dev/CI; выходы каталога keys/ в .gitignore.
#
# Генерируются:
#   * Ed25519 offline-ключ подписи артефактов (F-I-01) + публичная часть;
#   * X25519 ключ ECDH (Приложение Б);
#   * CA контура (EC P-256);
#   * серверный сертификат LLM Gateway (90 дней, ротация — runbook §3);
#   * пример краткоживущего клиентского сертификата D8 (TTL 5 мин, F-D-04);
#   * seed-ключ подписанта WORM для стенда (в prod — в TPM).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS_DIR="${1:-${ROOT}/keys}"

command -v openssl >/dev/null 2>&1 || { echo "gen-keys: openssl не найден" >&2; exit 1; }

mkdir -p "${KEYS_DIR}"
chmod 700 "${KEYS_DIR}"
cd "${KEYS_DIR}"

echo "== ZT-AI-CORE gen-keys → ${KEYS_DIR} =="

# 1. Ed25519 offline-ключ подписи артефактов (F-I-01)
if [[ ! -f artifact-signer.key ]]; then
    openssl genpkey -algorithm ED25519 -out artifact-signer.key
    openssl pkey -in artifact-signer.key -pubout -out artifact-signer.pub
    echo "  [+] artifact-signer (Ed25519)"
fi

# 2. X25519 — ECDH (Приложение Б п.1)
if [[ ! -f ecdh-x25519.key ]]; then
    openssl genpkey -algorithm X25519 -out ecdh-x25519.key
    openssl pkey -in ecdh-x25519.key -pubout -out ecdh-x25519.pub
    echo "  [+] ecdh-x25519"
fi

# 3. CA контура (EC P-256, 10 лет)
if [[ ! -f zt-ca.key ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out zt-ca.key
    openssl req -x509 -new -key zt-ca.key -sha256 -days 3650 \
        -subj "/O=ZT-AI-CORE/OU=Security/CN=ZT-AI-CORE Root CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out zt-ca.crt
    echo "  [+] zt-ca (Root CA)"
fi

# 4. Серверный сертификат LLM Gateway (90 дней — runbook §3)
if [[ ! -f gateway-server.key ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out gateway-server.key
    openssl req -new -key gateway-server.key \
        -subj "/O=ZT-AI-CORE/OU=L4-Gateway/CN=llm-gateway" \
        -out gateway-server.csr
    cat > gateway-server.ext <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:llm-gateway, DNS:localhost, IP:127.0.0.1
EOF
    openssl x509 -req -in gateway-server.csr -CA zt-ca.crt -CAkey zt-ca.key \
        -CAcreateserial -days 90 -sha256 -extfile gateway-server.ext \
        -out gateway-server.crt
    rm -f gateway-server.csr gateway-server.ext
    echo "  [+] gateway-server (90d, SAN: llm-gateway/localhost)"
fi

# 5. Клиентский сертификат D8 — TTL 5 минут (F-D-04), пример для стенда
GATEWAY_DIR="${ROOT}/submodules/llm-gateway"
if [[ -x "${GATEWAY_DIR}/certs/issue_short_lived.sh" ]]; then
    "${GATEWAY_DIR}/certs/issue_short_lived.sh" \
        "${KEYS_DIR}/zt-ca.crt" "${KEYS_DIR}/zt-ca.key" \
        "d8-rag-core" 300 "${KEYS_DIR}/d8-client" || \
        echo "  [!] краткоживущий клиентский сертификат не выпущен (см. выше)"
else
    echo "  [!] issue_short_lived.sh не найден — пропуск клиентского сертификата"
fi

# 6. Seed подписанта WORM для стенда (в prod — TPM/HSM, F-G-02)
if [[ ! -f worm-signing.seed ]]; then
    # os.urandom в CPython на Linux использует getrandom(2) — единственный
    # разрешённый источник случайности (Приложение Б п.4)
    python3 -c "import os,sys; sys.stdout.buffer.write(os.urandom(32))" \
        > worm-signing.seed
    chmod 600 worm-signing.seed
    echo "  [+] worm-signing.seed (32B, стенд; в prod — ключ в TPM)"
fi

chmod 600 ./*.key ./*.seed 2>/dev/null || true
chmod 644 ./*.crt ./*.pub 2>/dev/null || true

echo
echo "Готово. Содержимое ${KEYS_DIR}:"
find "${KEYS_DIR}" -maxdepth 1 -type f -printf "  %M %10s  %f\n" | sort
echo
echo "НАПОМИНАНИЕ: keys/ в .gitignore. В prod: Ed25519-подпись — только из"
echo "TPM/HSM (F-H-03), эмитент клиентских сертификатов — после Remote"
echo "Attestation (F-H-05)."
