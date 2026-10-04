# fsm-engine — детерминированный FSM-движок (L6)

Rust-реализация управления жизненным циклом ZT-AI-CORE (ТЗ v2.4, Раздел 3.4,
Приложение А, docs/05-fsm-matrix.md).

## Гарантии

* **Матрица Приложения А**: недопустимые комбинации Lifecycle×Mode отклоняются
  детерминированно (полный перебор 18 комбинаций в тестах);
* **WAL-атомарность (F-F-05)**: `Intent → fsync → применение → watchdog ack →
  Commit → fsync`; незавершённый переход при старте → принудительный
  `BOOT_FAILSAFE×RECOVERY` + повтор SELF_TEST (**AC-04**);
* **BLAKE3-контрольная сумма каждого кадра WAL** — битый кадр в середине файла
  трактуется как тамперинг (блокировка записи + инцидент);
* **Pending Rollback Counter (F-F-03)**: откат прошивки запрещён до успешного
  SELF_TEST; A/B-слоты (F-I-03), anti-downgrade `version_number` (F-I-02),
  Ed25519-проверка подписи артефакта (F-I-01);
* **Watchdog (NF-05)**: неподтверждение перехода ≤ 500 мс → форсированный
  RECOVERY;
* Реакция на события WORM: truncation → RECOVERY + write-lock (F-G-04);
  anchor down > 5 мин → DEGRADED; TPM wear ≥ 80% → DEGRADED (F-G-05).

## Модули

| Модуль | Назначение |
|---|---|
| `src/state.rs` | Lifecycle/Mode, матрица Приложения А, граф переходов |
| `src/wal.rs` | Бинарный WAL: кадр `ZTW1` + BLAKE3-checksum, recover/tail/truncate |
| `src/rollback.rs` | Pending Rollback Counter, A/B-слоты, подпись артефактов |
| `src/engine.rs` | Движок: переходы, watchdog, dump-state, обработчики WORM-событий |
| `src/server.rs` | UDS-сервер контракта `fsm.proto` (line-JSON dev-транспорт) |
| `src/audit.rs` | Клиент WORM-шины (публикация FSM_EVENT) |
| `src/main.rs` | CLI: `serve` / `healthcheck` / `dump` / `demo` |

## Использование

```bash
cargo test                          # 41 тест (матрица, WAL, rollback, watchdog)
cargo run -- demo --wal /tmp/wal.log
cargo run -- serve --socket /run/zt-core/fsm.sock --wal /var/lib/zt-fsm/wal.log \
                   --audit-socket /run/zt-core/audit.sock
cargo run -- dump --wal /var/lib/zt-fsm/wal.log      # форензика (runbook §2)
```

Wire-формат методов — `api/proto/fsm.proto` (GetState, RequestTransition,
RunSelfTest, StageUpdate, CommitUpdate, Rollback, GetRollbackStatus, DumpState,
GetWalTail). В prod-контуре dev-транспорт (line-JSON по UDS) заменяется на
gRPC-over-UDS без изменения схемы сообщений.
