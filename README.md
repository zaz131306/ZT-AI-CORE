ZT-AI-CORE — Zero-Trust AI Core (v2.4)

Enterprise-фреймворк изолированного когнитивного слоя для безопасного развёртывания ИИ-моделей (RAG-агентов) в аппаратно-программном изолированном контуре с нулевым доверием к когнитивному payload (домен D8).
Параметр 	Значение
Версия спецификации 	2.4 (Final, 100%) — docs/00-technical-specification.md
Стек 	Python 3.11+ (glibc), Rust 1.75+, gRPC/Protobuf, Bubblewrap, SECCOMP (custom BPF), eBPF, TPM 2.0
Платформы 	ARM64, x86_64, Nvidia Jetson (Orin/Xavier)
Нормативная база 	ISO/IEC 27001, ISO/IEC 42001, гражданские профили криптографии
Лицензия 	Apache License 2.0

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
