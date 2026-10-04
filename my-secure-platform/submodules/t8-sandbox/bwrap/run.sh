#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — запуск D8 в песочнице Bubblewrap (F-E-01, чек-лист §2 Шаг 1)
#
# Обязательные флаги ТЗ:  --unshare-net --unshare-pid --ro-bind / --die-with-parent
#
# ВАЖНО: на этом шаге bwrap запускается БЕЗ флага --seccomp — SECCOMP-фильтр
# применяется ИЗНУТРИ bootstrap.py (Шаг 5) строго после Eager Loading, warm-up
# и Capability Drop (Приложение В: «критическое архитектурное правило»).
#
# Использование:
#   run.sh [--mode strict|dev] [--profile <json>] [--dry-run] [-- <доп. аргументы python>]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- Конфигурация (переопределяется env) --------------------------------------
PYTHON_BIN="${ZT_PYTHON_BIN:-/usr/bin/python3.11}"
BOOTSTRAP_PY="${ZT_BOOTSTRAP_PY:-/opt/rag/bootstrap.py}"
RAG_ROOT="${ZT_RAG_ROOT:-/var/rag}"
SOCKET_DIR="${ZT_SOCKET_DIR:-/run/zt-core}"
PROFILE_MODE="${ZT_PROFILE_MODE:-strict}"   # strict | dev
PROFILE_JSON=""
DRY_RUN=0
MODE_OVERRIDE=""

usage() {
    cat <<EOF
Запуск D8 (когнитивного payload) под bwrap согласно ТЗ v2.4 (F-E-01).

Опции:
  --mode strict|dev   strict — боевой SECCOMP-профиль (Приложение В);
                      dev    — расширенный профиль + смягчённые проверки
  --profile <path>    явный путь к seccomp_profile*.json
  --dry-run           напечатать команду bwrap, не запуская
  --python <path>     интерпретатор (default: \$ZT_PYTHON_BIN или /usr/bin/python3.11)
  --bootstrap <path>  путь к bootstrap.py внутри sandbox (default: /opt/rag/bootstrap.py)
  -h, --help          эта справка
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)      MODE_OVERRIDE="$2"; shift 2 ;;
        --profile)   PROFILE_JSON="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=1; shift ;;
        --python)    PYTHON_BIN="$2"; shift 2 ;;
        --bootstrap) BOOTSTRAP_PY="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        --)          shift; break ;;
        *)           echo "run.sh: неизвестная опция: $1" >&2; usage; exit 64 ;;
    esac
done
EXTRA_ARGS=("$@")

[[ -n "${MODE_OVERRIDE}" ]] && PROFILE_MODE="${MODE_OVERRIDE}"

if [[ -z "${PROFILE_JSON}" ]]; then
    if [[ "${PROFILE_MODE}" == "dev" ]]; then
        PROFILE_JSON="${SANDBOX_ROOT}/bwrap/seccomp_profile_extended.json"
    else
        PROFILE_JSON="${SANDBOX_ROOT}/bwrap/seccomp_profile.json"
    fi
fi

# --- Предполётные проверки -----------------------------------------------------
fail() { echo "run.sh: FATAL: $*" >&2; exit 1; }

command -v bwrap >/dev/null 2>&1 || fail "bwrap не установлен (apt install bubblewrap)"
[[ -x "${PYTHON_BIN}" ]] || {
    # fallback: системный python3 (dev-контур); в prod — строго python3.11 glibc
    if [[ "${PROFILE_MODE}" == "dev" ]] && command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
        echo "run.sh: WARN: ${ZT_PYTHON_BIN:-/usr/bin/python3.11} не найден, dev-fallback: ${PYTHON_BIN}" >&2
    else
        fail "интерпретатор не найден: ${PYTHON_BIN} (F-E-08: требуется glibc python3.11)"
    fi
}
[[ -f "${PROFILE_JSON}" ]] || fail "SECCOMP-профиль не найден: ${PROFILE_JSON}"

# F-E-08: glibc, не musl (musl мигрирует на запрещённый clone3)
if "${PYTHON_BIN}" -c 'import platform,sys; sys.exit(0 if "glibc" in platform.libc_ver()[0].lower() or platform.libc_ver()[0]=="GNU C Library" else 1)' 2>/dev/null; then
    :
else
    if "${PYTHON_BIN}" -c 'import platform,sys; sys.exit(0 if platform.libc_ver()[0] else 1)'; then
        echo "run.sh: WARN: libc не определена как glibc — проверьте F-E-08 (musl запрещён)" >&2
    fi
fi

# Каталог сокетов IPC (F-E-04) — должен существовать до bwrap (rw-bind)
mkdir -p "${SOCKET_DIR}" 2>/dev/null || true
mkdir -p "${RAG_ROOT}" 2>/dev/null || true

# KSM-предупреждение (F-E-05, AC-07): для cgroup D8 KSM должен быть выключен
if [[ -r /sys/kernel/mm/ksm/run ]] && [[ "$(cat /sys/kernel/mm/ksm/run 2>/dev/null || echo 0)" != "0" ]]; then
    echo "run.sh: WARN: KSM активен (run=$(cat /sys/kernel/mm/ksm/run)) — требуется 'echo 0 > /sys/kernel/mm/ksm/run' (F-E-05)" >&2
fi

# --- Переменные окружения F-E-07 (анти-lazy-loading) ---------------------------
export PYTHONDONTWRITEBYTECODE=1
export GRPC_DISABLE_DYNAMIC_PLUGINS=1
export TORCH_DISABLE_DYNAMIC_JIT=1
# PYTHONPATH: пакеты песочницы доступны bootstrap.py внутри sandbox
ZT_SANDBOX_PYTHONPATH="${SANDBOX_ROOT}:${SANDBOX_ROOT}/seccomp"
if [[ -n "${PYTHONPATH:-}" ]]; then
    ZT_SANDBOX_PYTHONPATH="${ZT_SANDBOX_PYTHONPATH}:${PYTHONPATH}"
fi
export PYTHONPATH="${ZT_SANDBOX_PYTHONPATH}"
export ZT_SECCOMP_PROFILE="${PROFILE_JSON}"
export ZT_IN_BWRAP=1
export ZT_RAG_ROOT="${RAG_ROOT}"
export ZT_SOCKET_DIR="${SOCKET_DIR}"
export ZT_AUDIT_SPOOL="${ZT_AUDIT_SPOOL:-${RAG_ROOT}/audit-spool.jsonl}"

# --- Команда bwrap (чек-лист §2, Шаг 1) ----------------------------------------
# Обязательные флаги ТЗ (F-E-01):
#   --unshare-net     — полная изоляция сети (AC-01, первый рубеж)
#   --unshare-pid     — изоляция PID namespace
#   --ro-bind / /     — корень только для чтения
#   --die-with-parent — гарантия смерти D8 вместе с супервизором
# Дополнения (обоснованы):
#   --proc /proc      — корректный /proc/self в новом PID namespace
#                       (без него bootstrap не сможет читать maps/status)
#   --dev /dev        — минимальный /dev (null, zero, urandom недоступен по
#                       политике: случайность только getrandom(2))
#   --bind RAG_ROOT   — единственная rw-область данных (F-E-03)
#   --bind /tmp       — scratch (F-E-03)
#   --bind SOCKET_DIR — UDS-шина /run/zt-core (F-E-04)
BWRAP_CMD=(
    bwrap
    --unshare-net
    --unshare-pid
    --ro-bind / /
    --proc /proc
    --dev /dev
    --bind "${RAG_ROOT}" "${RAG_ROOT}"
    --bind /tmp /tmp
    --bind "${SOCKET_DIR}" "${SOCKET_DIR}"
    --die-with-parent
    --
    "${PYTHON_BIN}" "${BOOTSTRAP_PY}"
    --manifest "${SANDBOX_ROOT}/config/bootstrap_manifest.json"
    --seccomp-profile "${PROFILE_JSON}"
)
if [[ "${PROFILE_MODE}" == "dev" ]]; then
    BWRAP_CMD+=( --dev-mode )
fi
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    BWRAP_CMD+=( "${EXTRA_ARGS[@]}" )
fi

echo "run.sh: запуск D8 (mode=${PROFILE_MODE}, profile=${PROFILE_JSON})" >&2
if [[ "${DRY_RUN}" == "1" ]]; then
    printf '%q ' "${BWRAP_CMD[@]}"; printf '\n'
    exit 0
fi

exec "${BWRAP_CMD[@]}"
