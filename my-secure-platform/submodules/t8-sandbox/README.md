# t8-sandbox — граница изоляции D8 (L5)

Механизм песочницы когнитивного payload (ТЗ v2.4, Раздел 3.3, Приложение В,
чек-лист §2). Домен D5 — «среднее доверие»: слой не доверяет содержимому D8,
но жёстко контролирует периметр.

## Состав

| Путь | Назначение |
|---|---|
| `bwrap/run.sh` | Запуск D8 под Bubblewrap: `--unshare-net --unshare-pid --ro-bind / --die-with-parent` (F-E-01) |
| `bwrap/seccomp_profile.json` | **Строгий** SECCOMP-профиль Приложения В (default: `SCMP_ACT_KILL_PROCESS`) |
| `bwrap/seccomp_profile_extended.json` | Расширенный dev-профиль (жёсткие запреты те же; default `ERRNO(EPERM)`) |
| `seccomp/ztseccomp/` | Компилятор JSON → **custom classic BPF** + симулятор для offline-верификации |
| `ebpf/d8_guard.bpf.c` | eBPF-страж: drop `AF_INET/AF_INET6`, контроль `sun_path` (F-E-03) |
| `bootstrap.py` | **Bootstrap Sequence** (чек-лист §2, шаги 1–6) |
| `ztbootstrap/` | maps-baseline/diff, capability-контроль, IntegrityReport (F-E-06), WORM-спул |
| `grpc_client/zt_uds_client.py` | Клиент UDS-шины + валидация `sun_path` + `SO_PEERCRED` (F-E-04) |
| `config/bootstrap_manifest.json` | Манифест Eager Loading / warm-up / SECCOMP |
| `tests/` | 100+ тестов: симулятор политики, ядерные тесты (SIGSYS на AF_INET/clone3/PROT_EXEC), e2e bootstrap |

## Bootstrap Sequence (строгий порядок)

```text
Шаг 1  bwrap (без --seccomp)                    ← bwrap/run.sh
Шаг 2  execve /usr/bin/python3.11 (glibc!)      ← F-E-08
Шаг 3  EAGER LOADING: import всех C-extensions,
       загрузка весов, warm-up (1 forward pass),
       baseline /proc/self/maps                 ← F-E-07
Шаг 4  CAPABILITY DROP: PR_SET_NO_NEW_PRIVS,
       PR_CAPBSET_DROP (все cap), verify
       CapEff==CapPrm==CapInh==0, NNP==1        ← F-E-09, AC-10
Шаг 5  SECCOMP: SECCOMP_SET_MODE_FILTER
       (профиль Приложения В)                   ← F-E-02
Шаг 6  POST-VERIFY: сверка maps с baseline
       (расхождение → SIGKILL), IntegrityReport
       + SBOM (mismatch → BOOT_FAILSAFE),
       подключение к /run/zt-core/rag.sock      ← F-E-06/07, AC-05/09
```

## Ключевые свойства SECCOMP-фильтра (Приложение В)

* `clone` — только **точное** совпадение маски (`SCMP_CMP_EQ`):
  `0x10F00` (набор ТЗ) или `0x3D0F00` (точный набор glibc `pthread_create`);
* `clone3` — **полный запрет** (`KILL_PROCESS`);
* `mmap`/`mprotect` с `PROT_EXEC` → `KILL_PROCESS` (защита Eager Loading);
* `socket` — только `AF_UNIX`; `AF_INET/AF_INET6/AF_NETLINK/AF_PACKET` → явный KILL;
* `ioctl` — только `TCGETS`/`FIONBIO` (isatty/nonblock рантайма), остальное KILL;
* `newfstatat`/`statx` разрешены: glibc ≥ 2.33 реализует через них `fstat()`
  (F-E-08 требует glibc — без них группа «fstat» Приложения В неработоспособна;
  read-only метаданные, новой поверхности относительно `openat` не добавляют);
* arch-guard: чужой `AUDIT_ARCH` (включая x32-трюк `nr|0x40000000`) → KILL.

## Быстрый старт

```bash
# Компиляция профилей в BPF + верификация симулятором:
../../scripts/build-sec-profile.sh

# Тесты (симулятор + ЯДЕРНЫЕ тесты SIGSYS + e2e bootstrap):
PYTHONPATH=.:seccomp python3 -m pytest -q tests

# Запуск D8 (Linux-хост с bwrap):
bwrap/run.sh --mode dev --dry-run    # показать команду
bwrap/run.sh --mode dev              # dev-контур (extended-профиль)
bwrap/run.sh                         # боевой (строгий профиль)
```

## Документированные отклонения от литеры Приложения В

1. **`newfstatat`/`statx`** в whitelist (обоснование выше — glibc ABI).
2. **`ioctl` TCGETS/FIONBIO** — exact-match правила (isatty CPython,
   nonblock UDS-клиента); прочие ioctl-запросы убиваются.
3. **Вторая маска `clone` (0x3D0F00)** — точный набор флагов glibc
   `pthread_create`; остаётся exact EQ-match, wildcard не появляется.

Все три отклонения верифицируются симулятором (`ztseccomp.simulate`) и
ядерными тестами; строгая семантика «whitelist + KILL по умолчанию»
сохранена полностью.
