#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — сборка eBPF-стража D8 (F-E-03)
# Требует: clang >= 14 (target bpf), заголовки ядра (linux-libc-dev).
# Использование: build.sh [--check] [-o out.o]
#   --check — только компиляция во временный объект (для CI)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/d8_guard.bpf.c"
OUT="${SCRIPT_DIR}/d8_guard.bpf.o"
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        -o) OUT="$2"; shift 2 ;;
        -h|--help) echo "build.sh [--check] [-o out.o]"; exit 0 ;;
        *) echo "build.sh: неизвестная опция $1" >&2; exit 64 ;;
    esac
done

if ! command -v clang >/dev/null 2>&1; then
    echo "build.sh: clang не установлен — eBPF-объект не собран." >&2
    echo "          Debian/Ubuntu: apt install clang llvm" >&2
    exit 3
fi

if [[ ! -f /usr/include/linux/bpf.h ]]; then
    echo "build.sh: linux/bpf.h не найден — нужны заголовки ядра (linux-libc-dev)." >&2
    exit 3
fi

if [[ "${CHECK_ONLY}" == "1" ]]; then
    TMP_OUT="$(mktemp /tmp/d8_guard.XXXXXX.o)"
    trap 'rm -f "${TMP_OUT}"' EXIT
    KARCH_INCLUDE="/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
CLANG_BPF_FLAGS=(-O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86)
if [[ -d "${KARCH_INCLUDE}" ]]; then CLANG_BPF_FLAGS+=("-I${KARCH_INCLUDE}"); fi

clang "${CLANG_BPF_FLAGS[@]}" \
        -c "${SRC}" -o "${TMP_OUT}"
    echo "build.sh: --check OK (clang -target bpf, warnings as errors)"
    exit 0
fi

clang "${CLANG_BPF_FLAGS[@]}" \
    -c "${SRC}" -o "${OUT}"
echo "build.sh: собран ${OUT}"
cat <<'EOF'

Подключение (cgroup v2, от root на хосте):
  mkdir -p /sys/fs/bpf/zt
  bpftool prog loadall d8_guard.bpf.o /sys/fs/bpf/zt/d8_guard
  bpftool cgroup attach /sys/fs/cgroup/<d8-cgroup> sock_create \
      pinned /sys/fs/bpf/zt/d8_guard/d8_guard_sock_create
  bpftool cgroup attach /sys/fs/cgroup/<d8-cgroup> connect4 \
      pinned /sys/fs/bpf/zt/d8_guard/d8_guard_sock_create   # defense in depth
  bpftool cgroup attach /sys/fs/cgroup/<d8-cgroup> unix_connect \
      pinned /sys/fs/bpf/zt/d8_guard/d8_guard_unix_connect
EOF
