# Чек-лист реализации ZT-AI-CORE (v2.4)

*Обязателен к прочтению Lead Developer и DevOps перед началом Этапа 2.*

## 1. Подготовка окружения и зависимостей

- [ ] Базовый образ для D8 — **glibc** (Ubuntu/Debian), не `musl` (Alpine). Это обязательно для корректной работы `clone` без `clone3`.
- [ ] Отключить KSM для cgroup D8:
  - `echo 0 > /sys/kernel/mm/ksm/run`
  - или через cgroup v2: `echo 0 > /sys/fs/cgroup/<d8-cgroup>/memory.ksm`
- [ ] Настроить `isolcpus=` или `cpuset` для выделения Dedicated CPU ядер под D8 (снижение side-channel шума).
- [ ] Включить IMA appraisal policy для измерения рантайма D8.

## 2. Реализация Bootstrap Sequence (КРИТИЧНО!)

*Порядок в скрипте запуска D8 — строго такой:*

- [ ] **Шаг 1.** Запуск `bwrap` с базовой изоляцией:
  ```
  bwrap \
    --unshare-net --unshare-pid \
    --ro-bind / / \
    --bind /var/rag /var/rag \
    --bind /tmp /tmp \
    --die-with-parent \
    -- /usr/bin/python3.11 /opt/rag/bootstrap.py
  ```
  **БЕЗ флага `--seccomp`** на этом шаге.

- [ ] **Шаг 2.** `execve` целевого интерпретатора (`/usr/bin/python3.11`).

- [ ] **Шаг 3 (Eager Loading):**
  - `import` всех C-extensions немедленно: `torch`, `numpy`, `grpc`, `transformers`, и т.д.
  - Загрузка весов всех моделей (embedder, reranker, Qwen, NLI, validator).
  - **Warm-up:** выполнить 1 forward pass на dummy-данных для каждой модели.
  - Проверить, что lazy-loading отключён:
    - `PYTHONDONTWRITEBYTECODE=1`
    - `GRPC_DISABLE_DYNAMIC_PLUGINS=1`
    - `TORCH_DISABLE_DYNAMIC_JIT=1`
  - Запретить в RAG-ядре: `numba.jit`, `torch.compile`, `torch.jit.script` без предварительной компиляции, `cffi` с runtime-компиляцией.
  - **Baseline snapshot:** сохранить `/proc/self/maps` как baseline для последующей сверки.

- [ ] **Шаг 4 (Capability Drop):**
  - `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`
  - Для каждого capability в bounding set: `prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)`
  - Проверка `/proc/self/status`:
    - `CapEff: 0000000000000000`
    - `CapPrm: 0000000000000000`
    - `CapInh: 0000000000000000`
    - `NoNewPrivs: 1`
  - Если хотя бы одно условие не выполнено → `exit(1)`.

- [ ] **Шаг 5 (SECCOMP):**
  - Применение фильтра через `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`.
  - Профиль — строго из Приложения В ТЗ.
  - `clone` — с `SCMP_CMP_EQ` для маски флагов.
  - `clone3` — `SCMP_ACT_KILL_PROCESS`.
  - `mmap` с `PROT_EXEC` в runtime — кастомный BPF (`args[2] & PROT_EXEC` → KILL).

- [ ] **Шаг 6 (Post-SECCOMP verify):**
  - Сверка `/proc/self/maps` с baseline. Любое расхождение → SIGKILL.
  - Подключение к `/run/zt-core/rag.sock`.
  - Старт основного цикла RAG.

- [ ] **Тест:** После Шага 5 попытаться:
  - `import` новой библиотеки → ожидается SIGKILL.
  - `torch.jit.load` → ожидается SIGKILL.
  - `socket(AF_INET, ...)` → ожидается SIGKILL.

## 3. Настройка TPM и Remote Attestation

- [ ] Инициализировать TPM 2.0: EK (Endorsement Key), AK (Attestation Key).
- [ ] Настроить измерение PCR[8-15] при старте (хэши бинарников, конфигов, весов модели).
- [ ] Реализовать в LLM Gateway endpoint, требующий TPM Quote перед mTLS.
- [ ] Сверка PCR с эталоном из подписанного SBOM. Несовпадение → отказ соединения.

## 4. Настройка WORM и Anti-Truncation

- [ ] Реализовать счётчик записей и таймер (60 сек / 1000 записей) для триггера checkpoint.
- [ ] Настроить запись в TPM NV-Counter: не чаще 1 раза в час.
- [ ] Реализовать логику сверки при старте:
  - `seq_local < seq_TPM` → `systemctl start zt-recovery.service`.
  - `seq_local < seq_ext` → то же.
- [ ] Мониторинг износа NV-ячейки TPM (алерт при 80%).

## 5. Валидация и тестирование (Pre-Commit)

- [ ] Прогнать на всех подмодулях:
  - `trivy fs --severity HIGH,CRITICAL .`
  - `cargo-audit audit` (Rust)
  - `bandit -r .` (Python)
  - `gosec ./...` (Go)
  - `semgrep --config=auto .`
- [ ] Fuzzing gRPC-контрактов между D8 и L4 (`grpc-fuzz`).
- [ ] **Chaos-тесты (сценарии A–E):**
  - **A.** `tc qdisc add dev eth0 root netem delay 30000ms` — задержка LLM Gateway.
    Ожидание: D8 → `DEGRADED` ≤ 500 мс; fallback-ответ.
  - **B.** Блокировать UDP/53 через eBPF — DNS-отказ.
    Ожидание: LLM Gateway → offline, локальный Qwen продолжает.
  - **C.** Симулировать TPM NV write failure.
    Ожидание: WORM публикует checkpoint только в S3, система в `NOMINAL`, алерт.
  - **D.** S3 Object Lock → HTTP 503.
    Ожидание: через 5 мин → `DEGRADED`, checkpoint'ы в локальном буфере, потерь нет.
  - **E.** `kill -9` LLM Gateway.
    Ожидание: перезапуск ≤ 3 с, WORM фиксирует разрыв, D8 жив, при повторах — circuit breaker.
- [ ] Проверка воспроизводимости сборки: два независимых билда → одинаковые хэши артефактов.
- [ ] Сверка SBOM с фактическими зависимостями.

## 6. Финальная проверка перед релизом

- [ ] Все AC-01 … AC-10 пройдены.
- [ ] Все Chaos-сценарии A–E пройдены.
- [ ] TPM Quote сверяется с SBOM.
- [ ] WORM dual-anchor: TPM NV + S3 доступны и синхронизированы.
- [ ] Reproducible builds подтверждены.
- [ ] Документация `docs/00…09` синхронизирована с кодом.

---

**Конец чек-листа. Версия 2.4 (Final, 100%).**

---
