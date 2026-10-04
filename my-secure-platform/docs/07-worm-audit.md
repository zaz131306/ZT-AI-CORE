# WORM-аудит (L7): формат, чекпоинты, anti-truncation

**Источник:** ТЗ v2.4, Раздел 3.5 (F-G-01…F-G-05), Приложение Б п.3, runbook §5.
Реализация: `submodules/worm-audit/` (Rust).

## 1. Структура записи (F-G-01)

Append-only журнал. Каждая запись:

| Поле | Тип | Описание |
|---|---|---|
| `seq` | u64 | Монотонный номер записи (строго +1, без пропусков) |
| `payload_hash` | [u8;32] | BLAKE3 от payload (промпт, ответ, egress-запрос, IPC-событие…) |
| `timestamp` | u64 | Unix time, наносекунды (монотонный контроль: `ts_i ≥ ts_{i-1} − skew`) |
| `nonce` | [u8;16] | getrandom(); уникальность строго проверяется (anti-replay, F-G-03) |
| `previous_hash` | [u8;32] | `chain_hash` предыдущей записи (genesis = 32×0x00) |
| `record_signature` | [u8;64] | Ed25519-подпись записи (ключ в TPM/HSM; в dev — файловый провайдер) |
| `kind`, `source` | enum/string | Тип события (PROMPT/RESPONSE/EGRESS/IPC/OPERATOR/FSM_EVENT/INTEGRITY/VALIDATOR_VERDICT) и идентификатор компонента |

`chain_hash_i = BLAKE3(previous_hash ‖ payload_hash ‖ timestamp ‖ nonce)` (Приложение Б, п.3).

## 2. Чекпоинты (F-G-04)

- **Триггер:** ≥ 1000 записей **ИЛИ** ≥ 60 секунд с последнего чекпоинта.
- **Состав:** `{first_seq, last_seq, chain_head, timestamp, Ed25519-подпись}`.
- **Якорение в ДВУХ независимых местах:**
  1. **TPM NV-Counter** — offline-верификация; запись **не чаще 1 раза в час** (F-G-05);
  2. **Внешний WORM-сервис** (S3 Object Lock / отдельный узел) — при **каждом** чекпоинте.
- Если с последней TPM-записи прошло < 1 часа — чекпоинт идёт только в S3.
- Износ NV-ячейки TPM мониторится; **≥ 80% → `DEGRADED` + алерт** (F-G-05).

## 3. Anti-truncation: логика сверки при старте (F-G-04)

Пусть `seq_local` — последняя локальная запись, `seq_TPM` / `seq_ext` — заякоренные последовательности.

| Условие | Вердикт | Действие |
|---|---|---|
| `seq_TPM > seq_local` **или** `seq_ext > seq_local` | **TRUNCATION** | Немедленный `RECOVERY`, **блокировка записи**, инцидент безопасности → CISO (runbook §2) |
| `seq_local > seq_ext` | Норма (неподтверждённый хвост) | Публикация нового чекпоинта при первой возможности |
| `seq_local == seq_ext == seq_TPM` (или TPM отстаёт < 1 ч) | Норма | Продолжение работы |
| Внешний якорь недоступен > 5 минут | `EXT_ANCHOR_DOWN` | `DEGRADED`; запись продолжается; чекпоинты копятся в локальном защищённом буфере |
| TPM NV недоступен | `TPM_ANCHOR_DOWN` | Чекпоинты только в S3; `DEGRADED` до восстановления; затем `sync-tpm-nv` (runbook §5) |

**AC-03:** удаление хвоста лога → при старте `seq_local < seq_TPM` → `RECOVERY`.

## 4. Anti-replay (F-G-03)

- `nonce` отклоняется, если уже встречался в пределах TTL-окна (дефолт 300 с).
- `timestamp` вне окна `now ± TTL` → отклонение записи (`REJECTED_CLOCK`).
- Окно и ёмкость кэша nonce — конфигурируемы; кэш никогда не вытесняет «свежие» nonce.

## 5. Производительность и надёжность

- **NF-03:** ≥ 10 000 записей/с. Достигается групповым fsync (group-commit:
  каждые N записей / T мс) + BLAKE3 (SIMD). Политики синхронизации:
  `EveryRecord` (максимальная стойкость), `GroupCommit{n, interval}` (баланс, дефолт),
  `OnCheckpoint` (стенды).
- Хранилище: append-only JSONL + бинарный индекс; открытие только на допись (`O_APPEND`),
  ротация запрещена; восстановление — пересчёт цепочки от genesis/последнего чекпоинта.
- Потеря диска с логом: восстановление из S3 Object Lock → `rebuild-chain --from-s3` (runbook §5).

## 6. Мониторинг (метрики Prometheus, runbook §6)

| Метрика | Порог |
|---|---|
| `zt_worm_seq_local` vs `zt_worm_seq_ext` | расхождение → Critical |
| `zt_tpm_nv_wear` | > 80% → Warning |
| `zt_worm_append_latency_p99` | > 10 мс → Warning |
| `zt_worm_checkpoint_age_seconds` | > 120 с → Warning |

## 7. Покрытие аудита (NF-09: 100% действий)

В WORM обязаны писаться: промпты и ответы ИИ (F-D-03 п.4: хэш ответа + вердикт валидатора),
все egress-запросы LLM Gateway (F-D-04: хэш payload + метаданные), IPC-события,
операторские команды, FSM-переходы, результаты измерения целостности (F-E-06),
инциденты SECCOMP/eBPF.
