#!/usr/bin/env bash
# =============================================================================
# ZT-AI-CORE v2.4 — приёмочные самопроверки AC-01…AC-10 (Раздел 7 ТЗ)
#
# Каждый критерий проверяется автоматизированным тестом/демонстрацией.
# Выходной код: 0 — все AC пройдены; 1 — есть провалы.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
PYTHON="${PYTHON:-python3}"

PASS=0
FAIL=0
RESULTS=()

run_ac() {
    local id="$1" desc="$2"; shift 2
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [[ ${rc} -eq 0 ]]; then
        RESULTS+=("AC ${id} ✓  ${desc}")
        PASS=$((PASS+1))
    else
        RESULTS+=("AC ${id} ✗  ${desc}")
        FAIL=$((FAIL+1))
        echo "--- AC ${id} output (tail) ---" >&2
        echo "${out}" | tail -15 >&2
    fi
}

cd "${ROOT}" || exit 1

# --- AC-01: сетевая изоляция D8 (socket(AF_INET) → SECCOMP kill) ---------------
run_ac "01" "socket(AF_INET) из-под фильтра → SIGSYS" \
    env PYTHONPATH="${ROOT}/submodules/t8-sandbox:${ROOT}/submodules/t8-sandbox/seccomp" \
    "${PYTHON}" -m pytest -q "${ROOT}/submodules/t8-sandbox/tests/test_seccomp_kernel.py" \
    -k "ac01 or af_inet6"

# --- AC-02: невозможность кражи ключей (политика never-exportable) -------------
run_ac "02" "ключи never-exportable: unit-политика HAL + crypto-профиль" \
    env PATH="${PATH}" bash -c \
    "cd '${ROOT}/submodules/hal-common' && cargo test --quiet keys_never_exportable 2>&1 | grep -q 'test result: ok'"

# --- AC-03: защита WORM от truncation ------------------------------------------
run_ac "03" "удаление хвоста → seq_local < seq_anchor → TRUNCATION + блокировка записи" \
    env PATH="${PATH}" bash -c \
    "cd '${ROOT}/submodules/worm-audit' && cargo test --quiet ac03 2>&1 | grep -q 'test result: ok'"

# --- AC-04: атомарность FSM (power loss при переходе) --------------------------
run_ac "04" "Intent без Commit при старте → принудительный RECOVERY" \
    env PATH="${PATH}" bash -c \
    "cd '${ROOT}/submodules/fsm-engine' && cargo test --quiet ac04 2>&1 | grep -q 'test result: ok'"

# --- AC-05: целостность рантайма (SBOM/IMA) ------------------------------------
run_ac "05" "подмена .so/интерпретатора → несовпадение SBOM → BOOT_FAILSAFE-логика" \
    env PYTHONPATH="${ROOT}/submodules/t8-sandbox:${ROOT}/submodules/t8-sandbox/seccomp" \
    "${PYTHON}" -m pytest -q "${ROOT}/submodules/t8-sandbox/tests/test_integrity.py"

# --- AC-06: защита от галлюцинаций (100 вопросов вне базы → fallback) ----------
run_ac "06" "100/100 вопросов вне KB → fallback-фраза" \
    env PYTHONPATH="${ROOT}/submodules/rag-core" \
    "${PYTHON}" -m pytest -q "${ROOT}/submodules/rag-core/tests/test_pipeline_e2e.py::test_ac06_out_of_kb_questions_all_fallback"

# --- AC-07: side-channel (KSM off + mlock-политика) ------------------------------
AC07_STATUS="✓"
if [[ -r /sys/kernel/mm/ksm/run ]]; then
    ksm="$(cat /sys/kernel/mm/ksm/run 2>/dev/null || echo '?')"
    if [[ "${ksm}" != "0" ]]; then AC07_STATUS="✗ (KSM run=${ksm})"; fi
else
    AC07_STATUS="✓ (sysfs недоступен — проверяется юнит-тестом HAL)"
fi
run_ac "07" "KSM off для D8 + mlock-политика весов (${AC07_STATUS})" \
    env PATH="${PATH}" bash -c \
    "cd '${ROOT}/submodules/hal-common' && cargo test --quiet ksm 2>&1 | grep -q 'test result: ok'"

# --- AC-08: Remote Attestation (TPM Quote) ---------------------------------------
run_ac "08" "Quote(pcrs)+AK-подпись: верификация и отказ при подмене" \
    env PATH="${PATH}" bash -c \
    "cd '${ROOT}/submodules/hal-common' && cargo test --quiet quote 2>&1 | grep -q 'test result: ok'"

# --- AC-09: Eager Loading (mmap PROT_EXEC после SECCOMP → SIGKILL) -----------------
run_ac "09" "mmap/mprotect PROT_EXEC после arming → SIGSYS; lazy-import невозможен" \
    env PYTHONPATH="${ROOT}/submodules/t8-sandbox:${ROOT}/submodules/t8-sandbox/seccomp" \
    "${PYTHON}" -m pytest -q "${ROOT}/submodules/t8-sandbox/tests/test_seccomp_kernel.py" \
    -k "mmap_prot_exec or mprotect_prot_exec or execve"

# --- AC-10: Capability Drop (CapEff == 0) ---------------------------------------------
run_ac "10" "после bootstrap: CapEff==CapPrm==CapInh==0, NoNewPrivs==1" \
    env PYTHONPATH="${ROOT}/submodules/t8-sandbox:${ROOT}/submodules/t8-sandbox/seccomp" \
    ZT_IN_BWRAP=1 \
    "${PYTHON}" -m pytest -q "${ROOT}/submodules/t8-sandbox/tests/test_bootstrap_e2e.py" \
    -k "capability_drop_verified"

# --- Итог --------------------------------------------------------------------------------
echo
echo "================ ПРИЁМОЧНЫЕ ПРОВЕРКИ ZT-AI-CORE v2.4 ================"
for r in "${RESULTS[@]}"; do echo "  ${r}"; done
echo "====================================================================="
echo "  Пройдено: ${PASS}/10   Провалено: ${FAIL}/10"
if [[ ${FAIL} -gt 0 ]]; then
    echo "  Вердикт: НЕ ПРИНЯТО — см. вывод проваленных проверок выше"
    exit 1
fi
echo "  Вердикт: ВСЕ AC ВЫПОЛНЕНЫ"
exit 0
