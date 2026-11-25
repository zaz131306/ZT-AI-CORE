#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — компиляция SECCOMP-профиля JSON → custom BPF (Приложение В)
#
# Артефакты: submodules/t8-sandbox/seccomp/build/seccomp_<profile>_<arch>.bpf
#            + JSON-отчёты компиляции + верификация политики симулятором.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${ROOT}/submodules/t8-sandbox"
OUT_DIR="${SANDBOX}/seccomp/build"
PYTHON="${PYTHON:-python3}"

mkdir -p "${OUT_DIR}"
export PYTHONPATH="${SANDBOX}:${SANDBOX}/seccomp${PYTHONPATH:+:${PYTHONPATH}}"

PROFILES=("seccomp_profile" "seccomp_profile_extended")
ARCHES=("x86_64" "aarch64")

echo "== Компиляция SECCOMP-профилей (Приложение В ТЗ v2.4) =="
for profile in "${PROFILES[@]}"; do
    for arch in "${ARCHES[@]}"; do
        src="${SANDBOX}/bwrap/${profile}.json"
        out="${OUT_DIR}/${profile}_${arch}.bpf"
        report="${OUT_DIR}/${profile}_${arch}.report.json"
        echo "-> ${profile} / ${arch}"
        "${PYTHON}" -m ztseccomp.compile \
            --profile "${src}" --arch "${arch}" \
            --out "${out}" --report "${report}" | sed 's/^/   /'
    done
done

echo
echo "== Верификация политики симулятором cBPF (offline) =="
"${PYTHON}" - <<'PYEOF'
import sys
from pathlib import Path

sandbox = Path(__file__).resolve().parent if "__file__" in dir() else Path.cwd()
sys.path.insert(0, "submodules/t8-sandbox/seccomp")
sys.path.insert(0, "submodules/t8-sandbox")

from ztseccomp._tables_gen import SYSCALL_TABLES, AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64
from ztseccomp.profile import compile_profile
from ztseccomp.simulate import check_cases, simulate, strict_policy_cases

AUDIT = {"x86_64": AUDIT_ARCH_X86_64, "aarch64": AUDIT_ARCH_AARCH64}
failures = 0
for arch in ("x86_64", "aarch64"):
    prog, report = compile_profile(
        "submodules/t8-sandbox/bwrap/seccomp_profile.json", arch=arch)
    fails = check_cases(prog, arch, AUDIT[arch], SYSCALL_TABLES[arch],
                        strict_policy_cases(arch))
    # arch-guard: чужой AUDIT_ARCH → KILL
    r = simulate(prog, 1, AUDIT[arch] ^ 0xDEAD)
    if r.action_name != "KILL_PROCESS":
        fails.append(f"{arch}: wrong-arch не убит")
    print(f"strict/{arch}: insns={report.instruction_count}, "
          f"policy-checks FAILED={len(fails)}")
    for f in fails:
        print("  FAIL:", f)
    failures += len(fails)

# Ключевые инварианты расширенного профиля
for arch in ("x86_64", "aarch64"):
    prog, _ = compile_profile(
        "submodules/t8-sandbox/bwrap/seccomp_profile_extended.json", arch=arch)
    T = SYSCALL_TABLES[arch]
    checks = [
        ("clone3", (), "KILL_PROCESS"),
        ("socket", (2,), "KILL_PROCESS"),
        ("socket", (1,), "ALLOW"),
        ("mmap", (0, 4096, 7), "KILL_PROCESS"),
    ]
    fails = []
    for name, args, want in checks:
        if name not in T:
            continue
        got = simulate(prog, T[name], AUDIT[arch], args).action_name
        if got != want:
            fails.append(f"extended/{arch}: {name}{args} -> {got} != {want}")
    print(f"extended/{arch}: key-invariants FAILED={len(fails)}")
    for f in fails:
        print("  FAIL:", f)
    failures += len(fails)

sys.exit(1 if failures else 0)
PYEOF

echo
echo "== Готово: артефакты в ${OUT_DIR} =="
find "${OUT_DIR}" -maxdepth 1 -type f -printf "   %M %10s  %p\n" | sort
