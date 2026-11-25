#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — подготовка песочницы D8 на хосте (чек-лист §1, F-E)
#
# Шаги:
#   1. Предполётные проверки: bwrap, python3.11 (glibc), clang (опц.), заголовки;
#   2. Каталоги: /var/rag, /run/zt-core, /var/worm, /var/log/zt-core;
#   3. KSM off (F-E-05, AC-07);
#   4. Сборка eBPF-стража (если есть clang);
#   5. Компиляция SECCOMP-профилей (build-sec-profile.sh);
#   6. --sbom: генерация эталона SBOM для F-E-06 (интерпретатор + .so);
#   7. --cgroup: создание cgroup v2 для D8 с лимитами (memory.max=12G, KSM off);
#   8. --install-units: systemd-юниты (zt-worm-audit, zt-fsm-engine,
#      zt-llm-gateway, zt-rag-sandbox).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${ROOT}/submodules/t8-sandbox"
PYTHON_BIN="${ZT_PYTHON_BIN:-/usr/bin/python3.11}"
RAG_ROOT="${ZT_RAG_ROOT:-/var/rag}"
SOCKET_DIR="${ZT_SOCKET_DIR:-/run/zt-core}"
WORM_DIR="${ZT_WORM_DIR:-/var/worm}"
LOG_DIR="/var/log/zt-core"
DO_SBOM=0
DO_CGROUP=0
DO_UNITS=0
D8_MEMORY_MAX="${D8_MEMORY_MAX:-12G}"   # NF-06

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sbom) DO_SBOM=1; shift ;;
        --cgroup) DO_CGROUP=1; shift ;;
        --install-units) DO_UNITS=1; shift ;;
        -h|--help)
            echo "build-sandbox.sh [--sbom] [--cgroup] [--install-units]"; exit 0 ;;
        *) echo "неизвестная опция: $1" >&2; exit 64 ;;
    esac
done

step() { echo; echo "== $* =="; }
warn() { echo "WARN: $*" >&2; }

# --- 1. Предполётные проверки --------------------------------------------------
step "1/8 Предполётные проверки"
if command -v bwrap >/dev/null 2>&1; then
    echo "  bwrap: $(bwrap --version)"
else
    warn "bwrap не установлен (apt install bubblewrap) — запуск D8 невозможен"
fi
if [[ -x "${PYTHON_BIN}" ]]; then
    echo "  python: $(${PYTHON_BIN} --version 2>&1) (${PYTHON_BIN})"
else
    warn "${PYTHON_BIN} не найден (F-E-08: требуется glibc python3.11)"
    command -v python3 >/dev/null 2>&1 && \
        PYTHON_BIN="$(command -v python3)" && \
        echo "  fallback: ${PYTHON_BIN} ($(${PYTHON_BIN} --version 2>&1))"
fi
if ! "${PYTHON_BIN}" - <<'PY'
import platform, sys
libc = platform.libc_ver()[0].lower()
sys.exit(0 if libc in ("glibc", "gnu c library") else 1)
PY
then
    warn "интерпретатор не glibc — F-E-08 нарушен"
fi
if command -v clang >/dev/null 2>&1; then
    echo "  clang: $(clang --version | head -1)"
else
    warn "clang не установлен — eBPF-объект не будет собран"
fi

# --- 2. Каталоги ----------------------------------------------------------------
step "2/8 Каталоги контура"
for d in "${RAG_ROOT}" "${SOCKET_DIR}" "${WORM_DIR}" "${LOG_DIR}" \
         "${WORM_DIR}/anchors" "${WORM_DIR}/buffer" /var/lib/zt-fsm \
         /etc/zt-core/keys; do
    if mkdir -p "${d}" 2>/dev/null; then
        echo "  ${d}"
    else
        warn "нет прав на ${d}"
    fi
done
chmod 770 "${SOCKET_DIR}" 2>/dev/null || true

# --- 3. KSM off (F-E-05, AC-07) ---------------------------------------------------
step "3/8 KSM (side-channel, F-E-05)"
if [[ -w /sys/kernel/mm/ksm/run ]]; then
    echo 0 > /sys/kernel/mm/ksm/run
    echo "  KSM: run=$(cat /sys/kernel/mm/ksm/run) (должен быть 0)"
elif [[ -r /sys/kernel/mm/ksm/run ]]; then
    state="$(cat /sys/kernel/mm/ksm/run)"
    if [[ "${state}" != "0" ]]; then
        warn "KSM run=${state}, нет прав на выключение — выполните: echo 0 > /sys/kernel/mm/ksm/run"
    else
        echo "  KSM уже выключен"
    fi
else
    warn "/sys/kernel/mm/ksm недоступен (контейнер?) — пропуск"
fi

# --- 4. eBPF -----------------------------------------------------------------------
step "4/8 eBPF-страж D8 (F-E-03)"
if command -v clang >/dev/null 2>&1; then
    "${SANDBOX}/ebpf/build.sh" || warn "сборка eBPF не удалась"
else
    warn "clang отсутствует — eBPF не собран (defense-in-depth уровень пропущен)"
fi

# --- 5. SECCOMP-профили ----------------------------------------------------------------
step "5/8 SECCOMP-профили (Приложение В)"
"${ROOT}/scripts/build-sec-profile.sh" | tail -4

# --- 6. SBOM-эталон (F-E-06) -------------------------------------------------------------
if [[ "${DO_SBOM}" == "1" ]]; then
    step "6/8 Генерация эталона SBOM (F-E-06)"
    "${PYTHON_BIN}" - <<PY
import hashlib, json, os, sys
sys.path.insert(0, "${SANDBOX}")
interp = "${PYTHON_BIN}"

def sha256(p):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        return h.hexdigest()
    except OSError:
        return None

libs = {}
try:
    for line in open("/proc/self/maps"):
        parts = line.split()
        if len(parts) >= 6 and parts[-1].endswith((".so", ".so.2", ".so.6")) or ".so." in (parts[-1] if len(parts) >= 6 else ""):
            path = parts[-1]
            if path.startswith("/") and os.path.isfile(path):
                digest = sha256(path)
                if digest:
                    libs[path] = digest
except OSError as e:
    print(f"SBOM: maps scan error: {e}", file=sys.stderr)

sbom = {
    "format_version": "2.4",
    "interpreter_sha256": sha256(interp) or "",
    "libraries": libs,
    "model_weights_merkle_root": "",
    "_note": "сгенерировано build-sandbox.sh --sbom; в prod подписывается offline Ed25519 (F-I-01)",
}
out = "${SANDBOX}/config/sbom_reference.json"
with open(out, "w") as f:
    json.dump(sbom, f, ensure_ascii=False, indent=2)
print(f"  SBOM эталон: {out} (interpreter + {len(libs)} библиотек)")
PY
else
    echo; echo "== 6/8 SBOM: пропущен (--sbom) =="
fi

# --- 7. cgroup v2 для D8 -------------------------------------------------------------------
if [[ "${DO_CGROUP}" == "1" ]]; then
    step "7/8 cgroup v2 D8 (DoS-контрмеры, NF-06)"
    CG=/sys/fs/cgroup/zt-d8
    if [[ -d /sys/fs/cgroup && -w /sys/fs/cgroup/cgroup.controllers ]]; then
        mkdir -p "${CG}"
        echo "${D8_MEMORY_MAX}" > "${CG}/memory.max" 2>/dev/null || warn "memory.max не установлен"
        echo "+memory +pids +cpu" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
        echo "2048" > "${CG}/pids.max" 2>/dev/null || true
        if [[ -w "${CG}/memory.ksm" ]]; then echo 0 > "${CG}/memory.ksm"; fi
        echo "  cgroup ${CG}: memory.max=${D8_MEMORY_MAX} (NF-06)"
    else
        warn "cgroup v2 недоступен/нет прав — пропуск"
    fi
else
    echo; echo "== 7/8 cgroup: пропущен (--cgroup) =="
fi

# --- 8. systemd-юниты -------------------------------------------------------------------------
if [[ "${DO_UNITS}" == "1" ]]; then
    step "8/8 systemd-юниты"
    UNITS=/etc/systemd/system
    cat > "${UNITS}/zt-worm-audit.service" <<EOF
[Unit]
Description=ZT-AI-CORE WORM Audit (L7)
After=local-fs.target

[Service]
ExecStart=${ROOT}/submodules/worm-audit/target/release/zt-worm-audit serve --socket ${SOCKET_DIR}/audit.sock --chain ${WORM_DIR}/audit-chain.jsonl --checkpoints ${WORM_DIR}/checkpoints.jsonl --anchor-dir ${WORM_DIR}/anchors --tpm-dir /var/lib/zt-core/tpm-mock --signing-key /etc/zt-core/keys/worm-signing.seed
Restart=always
RestartSec=1
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${WORM_DIR} ${SOCKET_DIR} /var/lib/zt-core

[Install]
WantedBy=multi-user.target
EOF
    cat > "${UNITS}/zt-fsm-engine.service" <<EOF
[Unit]
Description=ZT-AI-CORE FSM Engine (L6)
After=zt-worm-audit.service

[Service]
ExecStart=${ROOT}/submodules/fsm-engine/target/release/zt-fsm-engine serve --socket ${SOCKET_DIR}/fsm.sock --wal /var/lib/zt-fsm/wal.log --audit-socket ${SOCKET_DIR}/audit.sock
Restart=always
RestartSec=1
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/zt-fsm ${SOCKET_DIR}

[Install]
WantedBy=multi-user.target
EOF
    cat > "${UNITS}/zt-llm-gateway.service" <<EOF
[Unit]
Description=ZT-AI-CORE LLM Gateway (L4)
After=zt-worm-audit.service

[Service]
Environment=ZT_GATEWAY_TLS_CERT=/etc/zt-core/keys/gateway-server.crt
Environment=ZT_GATEWAY_TLS_KEY=/etc/zt-core/keys/gateway-server.key
Environment=ZT_GATEWAY_CA=/etc/zt-core/keys/zt-ca.crt
Environment=ZT_GATEWAY_EGRESS_LOG=${LOG_DIR}/egress.jsonl
Environment=ZT_GATEWAY_AUDIT_SOCKET=${SOCKET_DIR}/audit.sock
ExecStart=$(command -v python3) -m llm_gateway.main --listen 0.0.0.0 --port 8443
WorkingDirectory=${ROOT}/submodules/llm-gateway
Restart=always
RestartSec=1
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF
    cat > "${UNITS}/zt-rag-sandbox.service" <<EOF
[Unit]
Description=ZT-AI-CORE D8 RAG Sandbox (L5/L8)
After=zt-fsm-engine.service zt-llm-gateway.service

[Service]
Environment=ZT_RAG_ROOT=${RAG_ROOT}
Environment=ZT_SOCKET_DIR=${SOCKET_DIR}
ExecStart=${SANDBOX}/bwrap/run.sh
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
    if systemctl daemon-reload; then echo "  юниты установлены: zt-worm-audit, zt-fsm-engine, zt-llm-gateway, zt-rag-sandbox"
    fi
    echo "  включение: systemctl enable --now zt-worm-audit zt-fsm-engine zt-llm-gateway zt-rag-sandbox"
else
    echo; echo "== 8/8 systemd: пропущен (--install-units) =="
fi

echo
echo "build-sandbox.sh завершён."
