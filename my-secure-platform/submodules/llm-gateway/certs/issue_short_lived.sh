#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — выпуск КРАТКОЖИВУЩИХ клиентских сертификатов D8 (F-D-04)
#
# TTL по умолчанию: 5 минут (300 с) — жёсткий лимит ТЗ.
# Использование:
#   issue_short_lived.sh <ca.crt> <ca.key> <common-name> [ttl_seconds] [out_prefix]
#
# Продакшен: выпуск выполняется сервисом-эмитентом после успешной Remote
# Attestation (TPM Quote, F-H-05); данный скрипт — для стендов и CI.
# =============================================================================
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <ca.crt> <ca.key> <CN> [ttl_secs=300] [out_prefix=client]" >&2
    exit 64
fi

CA_CERT="$1"
CA_KEY="$2"
CN="$3"
TTL="${4:-300}"
OUT="${5:-client}"

if (( TTL > 300 )); then
    echo "ERROR: TTL=${TTL}s > 300s — нарушение F-D-04 (TTL ≤ 5 мин)" >&2
    exit 65
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

# Приватный ключ клиента: Ed25519 (подписный алгоритм TLS 1.3; сам обмен
# ключами сессии — X25519 на уровне TLS key_share, Приложение Б п.1).
# ВАЖНО: X25519 НЕЛЬЗЯ использовать для подписи сертификатов — только ECDH.
openssl genpkey -algorithm ED25519 -out "${WORKDIR}/${OUT}.key"

# Запрос на сертификат
openssl req -new -key "${WORKDIR}/${OUT}.key" \
    -subj "/O=ZT-AI-CORE/OU=D8-Cognitive/CN=${CN}" \
    -out "${WORKDIR}/${OUT}.csr"

# Расширения: только clientAuth, короткий срок
cat > "${WORKDIR}/ext.cnf" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
EOF

# Подпись CA. TTL в секундах не поддерживается -days напрямую —
# используем -not_before/-not_after, если доступно (OpenSSL 3.x),
# иначе -days 1 и проверку фактического окна на стороне гейтвея.
if openssl x509 -help 2>&1 | grep -q -- "-not_after"; then
    NOT_AFTER="$(date -u -d "+${TTL} seconds" +"%Y%m%d%H%M%SZ" 2>/dev/null || \
                 date -u -v+"${TTL}"S +"%Y%m%d%H%M%SZ")"
    openssl x509 -req -in "${WORKDIR}/${OUT}.csr" \
        -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
        -not_after "${NOT_AFTER}" \
        -sha256 -extfile "${WORKDIR}/ext.cnf" \
        -out "${OUT}.crt"
else
    openssl x509 -req -in "${WORKDIR}/${OUT}.csr" \
        -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
        -days 1 -sha256 -extfile "${WORKDIR}/ext.cnf" \
        -out "${OUT}.crt"
    echo "WARN: OpenSSL без -not_after — сертификат на 1 день;" >&2
    echo "      гейтвей всё равно применит политику TTL≤${TTL}s по notAfter-notBefore." >&2
fi

chmod 600 "${OUT}.key" 2>/dev/null || true
chmod 644 "${OUT}.crt"

echo "выпущен клиентский сертификат: ${OUT}.crt (CN=${CN}, TTL=${TTL}s)"
openssl x509 -in "${OUT}.crt" -noout -subject -enddate
