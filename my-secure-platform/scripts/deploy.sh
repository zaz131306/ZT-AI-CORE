#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — развёртывание контура на хосте (scripts/deploy.sh)
#
# Порядок (идемпотентен, каждый шаг можно пропустить флагом):
#   1. build          — cargo build --release + python compileall + proto
#   2. keys           — scripts/gen-keys.sh
#   3. sandbox        — scripts/build-sandbox.sh (--sbom --cgroup по флагам)
#   4. units          — systemd-юниты (--install-units)
#   5. selftest       — scripts/run-self-test.sh (AC-01…AC-10)
#   6. up             — systemctl enable --now (только с --start)
#
# Использование:
#   deploy.sh [--dry-run] [--skip-selftest] [--install-units] [--start]
#             [--cgroup] [--sbom]
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

DRY=0
SKIP_SELFTEST=0
INSTALL_UNITS=0
START=0
CGROUP=0
SBOM=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY=1; shift ;;
        --skip-selftest) SKIP_SELFTEST=1; shift ;;
        --install-units) INSTALL_UNITS=1; shift ;;
        --start) START=1; shift ;;
        --cgroup) CGROUP=1; shift ;;
        --sbom) SBOM=1; shift ;;
        -h|--help)
            grep '^#' "$0" | head -20; exit 0 ;;
        *) echo "deploy.sh: неизвестная опция $1" >&2; exit 64 ;;
    esac
done

run() {
    echo "+ $*"
    if [[ "${DRY}" == "1" ]]; then echo "  (dry-run: пропущено)"; return 0; fi
    "$@"
}

step() { echo; echo "===== deploy: $* ====="; }

cd "${ROOT}"

step "1/5 build"
run make build

step "2/5 keys"
if [[ -d "${ROOT}/keys" && -f "${ROOT}/keys/zt-ca.crt" && "${DRY}" != "1" ]]; then
    echo "  ключи уже существуют — пропуск (ротация: runbook §3)"
else
    run "${ROOT}/scripts/gen-keys.sh"
fi

step "3/5 sandbox"
SANDBOX_FLAGS=()
[[ "${SBOM}" == "1" ]] && SANDBOX_FLAGS+=(--sbom)
[[ "${CGROUP}" == "1" ]] && SANDBOX_FLAGS+=(--cgroup)
[[ "${INSTALL_UNITS}" == "1" ]] && SANDBOX_FLAGS+=(--install-units)
run "${ROOT}/scripts/build-sandbox.sh" ${SANDBOX_FLAGS[@]+"${SANDBOX_FLAGS[@]}"}

step "4/5 selftest (AC-01…AC-10)"
if [[ "${SKIP_SELFTEST}" == "1" ]]; then
    echo "  пропущено (--skip-selftest)"
else
    run "${ROOT}/scripts/run-self-test.sh"
fi

step "5/5 start"
if [[ "${START}" == "1" && "${INSTALL_UNITS}" == "1" ]]; then
    run systemctl enable --now zt-worm-audit zt-fsm-engine zt-llm-gateway
    run systemctl start zt-rag-sandbox
    echo "  порядок старта: worm-audit → fsm-engine → llm-gateway → D8 sandbox"
else
    echo "  автозапуск пропущен (нужны --install-units --start)"
fi

echo
echo "deploy.sh завершён. Runbook: docs/02-runbook.md"
