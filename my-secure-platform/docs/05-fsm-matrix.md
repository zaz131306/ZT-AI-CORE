# Матрица FSM и правила переходов (L6)

**Источник:** ТЗ v2.4, Раздел 3.4 (F-F-01…F-F-05), Приложение А, Раздел 3.7 (F-I-02, F-I-03).
Реализация: `submodules/fsm-engine/` (Rust).

## 1. Пространство состояний

- **Lifecycle (F-F-01):** `BOOT → BOOT_FAILSAFE → SELF_TEST → RUNNING → DEGRADED → SHUTDOWN`
- **Operating Modes (F-F-02):** `NOMINAL`, `ISOLATED`, `RECOVERY`

## 2. Приложение А. Матрица допустимых комбинаций (Lifecycle × Mode)

| Lifecycle \ Mode | NOMINAL | ISOLATED | RECOVERY |
|---|---|---|---|
| **BOOT** | ✅ | ❌ | ❌ |
| **BOOT_FAILSAFE** | ❌ | ❌ | ✅ |
| **SELF_TEST** | ✅ | ✅ | ❌ |
| **RUNNING** | ✅ | ✅ | ✅ |
| **DEGRADED** | ❌ | ✅ | ✅ |
| **SHUTDOWN** | ✅ | ✅ | ✅ |

Комбинация, не отмеченная ✅, **запрещена**: движок отклоняет переход
(`TransitionResponse.accepted = false`) и пишет событие отказа в WORM.

## 3. Граф переходов lifecycle

```text
                 ┌──────────────┐  integrity/IMA fail   ┌────────────────┐
                 │     BOOT     │ ────────────────────> │  BOOT_FAILSAFE │
                 └──────┬───────┘                       └───────┬────────┘
                        │ boot ok                               │ (только RECOVERY-режим)
                        v                                       v
                 ┌──────────────┐   self-test fail      ┌──────────────┐
        ┌──────> │  SELF_TEST   │ ────────────────────> │   RECOVERY*  │
        │        └──────┬───────┘                       └──────┬───────┘
        │               │ pass                                 │ remediation ok
        │               v                                      │
        │        ┌──────────────┐   anchor down > 5 мин        │
        │        │   RUNNING    │ ──────────────> DEGRADED     │
        │        └──────┬───────┘                  │    │      │
        │               │ truncation / WAL intent  │    │ recovered
        │               v                          v    └──────┤
        │        ┌──────────────┐            (возврат в SELF_TEST)
        └─────── │   RECOVERY*  │ <────────────────────────────┘
                 └──────┬───────┘
                        │ operator shutdown
                        v
                 ┌──────────────┐
                 │   SHUTDOWN   │
                 └──────────────┘
* RECOVERY — forced mode при незавершённом WAL-переходе (F-F-05)
```

## 4. Атомарность переходов (F-F-05)

1. Перед сменой состояния в **WAL** пишется пара записей:
   `Intent { from, to, mode, epoch, seq }` → `fsync` → применение → `Commit { seq }` → `fsync`.
2. Переход считается завершённым только после записи `Commit` **и подтверждения watchdog**.
3. **При старте:** сканирование WAL; найден `Intent` без `Commit` → принудительный режим
   `RECOVERY` + повтор `SELF_TEST` (AC-04: питание сброшено при переходе → старт в RECOVERY).
4. WAL размещается на выделенном разделе/файле с гарантированным `fsync`
   (в продакшене — TPM NV-RAM для критичных полей; в dev — файл `wal.log` + BLAKE3-контрольная
   сумма каждой записи).

## 5. Pending Rollback Counter (F-F-03) и A/B-обновления (F-I-03)

| Событие | Счётчик | Разрешение rollback |
|---|---|---|
| `stage_update(Slot B, version N+1)` | `pending += 1` | ❌ запрещён (идёт подготовка) |
| Старт с Slot B, `SELF_TEST` **не завершён** | без изменений | ❌ **запрещён** (F-F-03: откат до успешного SELF_TEST недопустим) |
| `SELF_TEST` в Slot B: **успех** → `commit` | `pending = 0` | Slot A обновляется атомарно; monotonic `version_number` (F-I-02, anti-downgrade в TPM NV) |
| `SELF_TEST` в Slot B: **провал** | `pending = 0` | ✅ разрешён и обязателен: rollback к Slot A, инцидент в WORM |

Инвариант движка: `rollback_allowed == true` **только** при `pending_rollback_counter == 0`
или при зафиксированном провале `SELF_TEST` нового слота.

## 6. Консенсус (F-F-04)

- **Кластерные узлы:** Raft-репликация WAL переходов (кворум ≥ ⌈N/2⌉+1).
- **Edge (Jetson):** локальный кворумный лог — WAL + dual-anchor WORM (TPM NV + S3)
  как внешний свидетель последовательности состояний.

## 7. Тайминги (NF-05)

- Детекция сбоя + начало перехода: **≤ 500 мс**.
- Полная стабилизация (включая `SELF_TEST`): **≤ 5 с**.
- Watchdog: отсутствие подтверждения перехода > 500 мс → форсированный `RECOVERY`.

## 8. Триггеры переходов (сводно)

| Триггер | Переход |
|---|---|
| IMA/dm-verity несовпадение, SBOM mismatch (F-E-06) | `BOOT → BOOT_FAILSAFE (RECOVERY)` |
| Truncation WORM: `seq_local < seq_TPM` или `seq_local < seq_ext` (F-G-04) | `* → RECOVERY`, блокировка записи |
| Внешний WORM-якорь (S3) недоступен > 5 мин (F-G-04) | `RUNNING → DEGRADED` |
| Износ TPM NV ≥ 80% (F-G-05) | `RUNNING → DEGRADED` + алерт |
| LLM Gateway не отвечает > 30 с (runbook §1) | `RUNNING → DEGRADED` |
| Незавершённый WAL-intent при старте (F-F-05) | старт в `RECOVERY` |
| Провал `SELF_TEST` | `SELF_TEST → RECOVERY` |
| Оператор / плановое завершение | `* → SHUTDOWN` |
