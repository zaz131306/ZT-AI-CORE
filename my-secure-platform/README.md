# ZT-AI-CORE — Zero-Trust AI Core (v2.4)

**Enterprise-фреймворк изолированного когнитивного слоя** для безопасного развёртывания
ИИ-моделей (RAG-агентов) в аппаратно-программном изолированном контуре с нулевым доверием
к когнитивному payload (домен D8).

| Параметр | Значение |
|---|---|
| Версия спецификации | **2.4 (Final, 100%)** — `docs/00-technical-specification.md` |
| Стек | Python 3.11+ (glibc), Rust 1.75+, gRPC/Protobuf, Bubblewrap, SECCOMP (custom BPF), eBPF, TPM 2.0 |
| Платформы | ARM64, x86_64, Nvidia Jetson (Orin/Xavier) |
| Нормативная база | ISO/IEC 27001, ISO/IEC 42001, гражданские профили криптографии |
| Лицензия | Apache License 2.0 |

## Гарантии безопасности (кратко)

Система гарантирует, что ИИ (D8) **не сможет**:

1. Осуществить сетевой побег — весь внешний трафик только через L4-прокси (LLM Gateway);
   в D8: `--unshare-net` + SECCOMP-kill `AF_INET/AF_INET6` + eBPF-drop.
2. Прочитать/изменить системные файлы, память хоста или крипто-ключи —
   `--ro-bind /`, capability drop (`CapEff == 0`), ключи never-exportable в TPM/HSM.
3. Повлиять на критические исполнительные органы (L0–L4) без валидации детерминированным FSM.
4. Скрыть следы своей работы — 100% WORM-аудит: BLAKE3 hash-chain, Ed25519-чекпоинты,
   dual-anchor anti-truncation (TPM NV-Counter + S3 Object Lock).

## Структура репозитория (Раздел 5 ТЗ)

```text
my-secure-platform/
├── README.md
├── LICENSE                          # Apache 2.0
├── docs/                            # 00–09: ТЗ, threat model, чек-лист, runbook, слои,
│                                    # домены, FSM-матрица, крипто-профиль, WORM, песочница, HAL
├── submodules/
│   ├── t8-sandbox/                  # L5: bwrap, SECCOMP (custom BPF), eBPF, gRPC-client (UDS)
│   ├── fsm-engine/                  # L6 (Rust): states, transitions, WAL, Pending Rollback Counter
│   ├── worm-audit/                  # L7 (Rust): BLAKE3-chain, Ed25519 checkpoints, anti-truncation
│   ├── hal-common/                  # L2–L3 (Rust): crypto, thermal, power, platform, TPM
│   ├── llm-gateway/                 # L4 (Python): mTLS-прокси, Egress DLP, rate-limit, circuit breaker
│   └── rag-core/                    # L8 (Python): ingestion, KB, retriever, llm-client, каскадный валидатор
├── api/proto/                       # Контракты gRPC: sandbox.proto, fsm.proto, audit.proto, rag.proto
├── scripts/                         # build-sec-profile, build-sandbox, run-self-test, gen-keys, deploy
├── tests/fuzz/                      # Fuzzing IPC/gRPC-контрактов (этап 7 ТЗ)
├── docker-compose.yml               # llm-gateway, rag-core, worm-audit, fsm-engine
├── Makefile                         # build | test | fuzz | sec-scan | docker-run | clean
└── .github/workflows/               # ci.yml, security-scan.yml
```

## Быстрый старт

```bash
# 1. Развернуть репозиторий из единого генератора (если начинаете с init_repo.sh):
./init_repo.sh ./my-secure-platform && cd my-secure-platform

# 2. Собрать всё (Rust release + byte-compile Python + валидация proto):
make build

# 3. Прогнать все тесты (cargo test, pytest, shellcheck, protoc):
make test

# 4. Security-сканеры и fuzzing контрактов:
make sec-scan
make fuzz

# 5. Dev-контур в контейнерах (4 сервиса ТЗ):
make docker-run

# 6. Приёмочные проверки AC-01…AC-10 (на Linux-хосте):
scripts/run-self-test.sh

# Запуск D8 в песочнице (требует bwrap, glibc-хост):
submodules/t8-sandbox/bwrap/run.sh
```

## Архитектура (слои и домены)

```text
 Внешние LLM API (allow-list)
        ▲ mTLS (TTL≤5мин) + TPM Quote (Remote Attestation)
 ┌──────┴───────────────────────────────────────────────────────────┐
 │ L4  llm-gateway: DLP · rate-limit · circuit-breaker · WORM-egress │  D4 (высокое доверие)
 └──────▲───────────────────────────────────────────────────────────┘
        │ AF_UNIX gRPC (/run/zt-core/rag.sock, SO_PEERCRED)
 ═══════╪══════════ L5 SANDBOX BOUNDARY: bwrap · SECCOMP · eBPF ═════  D5 (граница доверия)
 ┌──────┴─────────────────────────────┐
 │ L8  D8 COGNITIVE PAYLOAD (нулевое  │   ┌────────────────────────────┐
 │ доверие): rag-core + Qwen 2.5      │   │ L6 fsm-engine (WAL, A/B)   │ D6
 │ · Eager Loading · CapDrop · SECCOMP│   │ L7 worm-audit (BLAKE3,     │ D7
 └────────────────────────────────────┘   │ Ed25519, TPM NV + S3)      │
                                          └────────────────────────────┘
 L0–L3: HW · Kernel(IMA/cgroup) · TPM2.0/HSM · Crypto (AES-256-GCM, Ed25519, X25519, BLAKE3)
```

Подробности: `docs/03-layers.md`, `docs/04-domains.md`, `docs/05-fsm-matrix.md`.

## Ключевые механизмы

| Механизм | Где реализован | Требование ТЗ |
|---|---|---|
| Bootstrap Sequence (Eager Loading → Warm-up → CapDrop → SECCOMP → maps-verify) | `submodules/t8-sandbox/bootstrap.py` | F-E-07, F-E-09, чек-лист §2 |
| Custom BPF-компилятор SECCOMP-профиля (exact-match `clone`, ban `clone3`, `PROT_EXEC` guard) | `submodules/t8-sandbox/seccomp/ztseccomp/` | F-E-02, Приложение В |
| FSM: матрица Lifecycle×Mode, WAL-атомарность, Pending Rollback Counter, A/B-slots | `submodules/fsm-engine/` | F-F-01…05, F-I-02/03, AC-04 |
| WORM: BLAKE3 hash-chain, Ed25519-чекпоинты, nonce/TTL anti-replay, dual-anchor reconcile | `submodules/worm-audit/` | F-G-01…05, AC-03 |
| LLM Gateway: mTLS (TTL ≤ 5 мин), Egress DLP (PII/секреты), token-bucket, circuit breaker, allow-list | `submodules/llm-gateway/` | F-D-04 |
| RAG: чанкинг 300–800 токенов (overlap 10–15%), гибрид vector+BM25+rerank, каскадный валидатор (rules → cos-sim 0.85/0.60 → NLI → fallback), изоляция промпта | `submodules/rag-core/` | F-A…F-C, F-D-03, AC-06 |
| HAL: крипто-профиль, тепловой бюджет T_j ≤ 75 °C, power-бюджеты NF-07, TPM-операции | `submodules/hal-common/` | F-H-01…05, NF-06…08 |

## Критерии приёмки (Раздел 7 ТЗ)

AC-01 (сетевая изоляция), AC-02 (нет ключей в D8), AC-03 (anti-truncation), AC-04 (WAL-атомарность),
AC-05 (целостность рантайма), AC-06 (100% fallback вне базы), AC-07 (KSM off + mlock),
AC-08 (Remote Attestation), AC-09 (Eager Loading), AC-10 (CapEff == 0) —
автоматизированы в `scripts/run-self-test.sh` и тестах подмодулей.

## Документация

| Файл | Содержание |
|---|---|
| `docs/00-technical-specification.md` | Полное ТЗ v2.4 (архитектура, криптография, реализация, безопасность) |
| `docs/00-threat-model.md` | STRIDE + MITRE ATLAS |
| `docs/01-implementation-checklist.md` | Чек-лист реализации (bootstrap, TPM, WORM, chaos A–E) |
| `docs/02-runbook.md` | Операционный runbook (DEGRADED/RECOVERY, ключи, A/B, метрики) |
| `docs/03…09` | Слои, домены, FSM-матрица, крипто-профиль, WORM, песочница, HAL/thermal |

## Статус и ограничения

Репозиторий содержит **рабочие референс-реализации** ключевых блоков v2.4: все модули
собираются и проходят тесты (`make test`). Продакшен-интеграции, требующие целевого железа
(TPM 2.0, HSM, S3 Object Lock, Jetson-телеметрия), выполнены как trait/adapter-интерфейсы
с детерминированными mock-реализациями для CI — точки подключения описаны в `docs/02-runbook.md`
и комментариях кода. Транспорт gRPC-контрактов (`api/proto/`) в dev-контуре заменён
line-oriented JSON по UDS (тот же контракт полей); codegen-заглушки генерируются `make proto`.

## Лицензия

Apache License 2.0 — см. [LICENSE](LICENSE).
