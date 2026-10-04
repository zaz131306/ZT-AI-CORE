# Конфигурация песочницы D8 (L5)

**Источник:** ТЗ v2.4, Раздел 3.3 (F-E-01…F-E-09), Приложение В, чек-лист §1–2.
Реализация: `submodules/t8-sandbox/`.

## 1. Bubblewrap (F-E-01)

Базовый запуск (чек-лист, Шаг 1 — **без `--seccomp`**, фильтр применяется изнутри bootstrap):

```bash
bwrap \
  --unshare-net --unshare-pid \
  --ro-bind / / \
  --bind /var/rag /var/rag \
  --bind /tmp /tmp \
  --die-with-parent \
  -- /usr/bin/python3.11 /opt/rag/bootstrap.py
```

Дополнительно в `bwrap/run.sh` (обосновано в комментариях): `--proc /proc` (корректный
`/proc/self` в новом PID-namespace), `--dev /dev`, rw-bind `/run/zt-core` (UDS-сокеты),
env: `PYTHONDONTWRITEBYTECODE=1`, `GRPC_DISABLE_DYNAMIC_PLUGINS=1`, `TORCH_DISABLE_DYNAMIC_JIT=1`.

## 2. SECCOMP-профиль (F-E-02, Приложение В)

- Формат профиля: `bwrap/seccomp_profile.json` (first-match-wins, дефолт `SCMP_ACT_KILL_PROCESS`).
- Компилятор JSON → classic BPF: `seccomp/ztseccomp/` (архитектуры x86_64 и aarch64,
  контроль `audit_arch`, 64-битные аргументы двумя 32-битными загрузками).
- Ключевые правила:
  - `clone` — только **точное совпадение** маски флагов (`SCMP_CMP_EQ`):
    `CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD` (+ точная маска glibc-pthread,
    см. комментарий в профиле — тоже EQ, без wildcard);
  - `clone3` — **полный запрет** (`SCMP_ACT_KILL_PROCESS`): аргументы передаются указателем
    на структуру и не проверяются чистым seccomp без `seccomp_unotify`;
  - `mmap`/`mprotect` с `PROT_EXEC` (`args[2] & 0x4`) — KILL (кастомный BPF);
  - `socket` — только `AF_UNIX` (`args[0] == 1`); `AF_INET`/`AF_INET6` — явный KILL;
  - запрещены: `execve`/`execveat` (после bootstrap), `ptrace`, `mount`, `umount`, `chroot`,
    `pivot_root`, `bpf`.
- Полный whitelist — в Приложении В ТЗ (`docs/00-technical-specification.md`) и в JSON-профиле.

## 3. eBPF (F-E-03)

`ebpf/d8_guard.bpf.c`: LSM/cgroup-хуки — блокировка `socket(AF_INET/AF_INET6)` для cgroup D8,
контроль путей ФС (только `/tmp`, `/var/rag`, `/run/zt-core/*.sock`), проверка `sun_path`.
Сборка: `ebpf/build.sh` (clang `-target bpf`). eBPF — второй рубеж после SECCOMP (defense in depth).

## 4. IPC (F-E-04)

- Только gRPC/Protobuf по **Unix Domain Sockets** (`/run/zt-core/rag.sock` и др.).
- Серверная сторона проверяет `SO_PEERCRED` (uid/gid/pid клиента) и валидирует `sun_path`.
- Клиент: `grpc_client/rag_uds_client.py`.

## 5. Side-channel (F-E-05)

- KSM **отключён** для cgroup D8: `echo 0 > /sys/kernel/mm/ksm/run`
  (или cgroup v2 `memory.ksm`); метрика `zt_d8_ksm_active` должна быть 0 (AC-07).
- Крипто-буферы и веса модели — `mlock()` (запрет свопа/дедупликации).
- Выделенные ядра: `isolcpus=` / cpuset cgroup. ARM: TZASC для памяти крипто-операций L3.

## 6. Bootstrap Sequence (F-E-07, F-E-09; чек-лист §2 — порядок строгий)

1. **bwrap** с базовой изоляцией (без `--seccomp`).
2. **execve** целевого интерпретатора `/usr/bin/python3.11` (glibc — F-E-08; musl запрещён:
   мигрирует на запрещённый `clone3`).
3. **Eager Loading:** немедленный `import` всех C-extensions (torch, numpy, grpc, transformers…),
   загрузка весов всех моделей, **warm-up** (1 forward pass на dummy-данных для каждой модели),
   env-флаги анти-lazy, запрет `numba.jit`/`torch.compile`/`torch.jit.script` без
   прекомпиляции/`cffi` runtime-compile; **baseline snapshot** `/proc/self/maps`.
4. **Capability Drop:** `prctl(PR_SET_NO_NEW_PRIVS,1)`; `prctl(PR_CAPBSET_DROP, cap)` для
   каждого cap в bounding set; проверка `/proc/self/status`:
   `CapEff == CapPrm == CapInh == 0`, `NoNewPrivs == 1`; иначе `exit(1)`.
5. **SECCOMP:** `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` — профиль строго из Приложения В.
6. **Post-SECCOMP verify:** сверка `/proc/self/maps` с baseline (любое расхождение → SIGKILL),
   подключение к `/run/zt-core/rag.sock`, старт основного цикла RAG.

**Негативные тесты (после Шага 5):** `import` новой библиотеки → SIGKILL;
`torch.jit.load` → SIGKILL; `socket(AF_INET,…)` → SIGKILL (AC-01, AC-09, AC-10).

## 7. Измерение целостности рантайма (F-E-06)

При каждом старте D8 в WORM пишутся: SHA-256 интерпретатора, список загруженных `.so`
(из `/proc/self/maps`), Merkle-root весов модели. Несовпадение с эталоном из подписанного
SBOM → `BOOT_FAILSAFE` (политика IMA appraisal; AC-05).
