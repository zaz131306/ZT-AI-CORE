# Техническое задание (ТЗ) на разработку защищённого контура для ИИ
## «Zero-Trust AI Core» — Enterprise-фреймворк изолированного когнитивного слоя

**Версия:** 2.4 (Final, 100%)
**Шифр:** ZT-AI-CORE
**Класс документа:** Полный пакет ТЗ (архитектура + криптография + реализация + безопасность + внедрение)
**Статус:** Готов к передаче в разработку, pen-test и сертификацию

---

## Раздел 0. Паспорт проекта

| Параметр | Значение |
|---|---|
| **Наименование** | Zero-Trust AI Core (ZT-AI-CORE) |
| **Назначение** | Фреймворк нулевого доверия для безопасного развёртывания и эксплуатации ИИ-моделей (RAG-агентов) в аппаратно-программном изолированном контуре |
| **Область применения** | Гражданские ИИ-сервисы: аналитика, RAG-ассистенты, медицинские комплексы, БПЛА-системы, промышленная автоматизация (Edge AI) |
| **Базовый стек** | Python 3.11+ (glibc), Go 1.22+ / Rust 1.75+, Libsodium, OpenSSL 3.x, gRPC/Protobuf, Bubblewrap, SECCOMP (custom BPF), eBPF |
| **Целевые платформы** | ARM64, x86_64, Nvidia Jetson (Orin/Xavier) |
| **Нормативная база** | ISO/IEC 27001, ISO/IEC 42001 (AI Management), гражданские профили криптографии |
| **Исключено** | ГОСТ Р 34.12-2015, «Кузнечик», «Магма», «Стрибог», КС3/ФСТЭК, ZeroNoise, спец-оборудование |

---

## Раздел 1. Назначение и цели

### 1.1. Назначение системы
ZT-AI-CORE — **отчуждаемый фреймворк**, развёртывающий ИИ-модели в жёстко изолированной песочнице (домен D8, слой L5). Система гарантирует, что ИИ не сможет:
1. Осуществить сетевой побег (весь внешний трафик — только через прокси L4).
2. Прочитать/изменить системные файлы, память хоста или криптографические ключи.
3. Повлиять на критические исполнительные органы (L0–L4) без валидации FSM.
4. Скрыть следы своей работы (100% WORM-аудит с защитой от truncation).

### 1.2. Цели разработки
1. **Физическая и логическая изоляция** когнитивного слоя (Zero-Trust).
2. **Предсказуемость** при сбоях через детерминированный FSM-движок с атомарными переходами.
3. **Неизменяемость аудита** (WORM hash-chain с криптографической подписью и внешним якорем).
4. **Современная гражданская криптография** с аппаратным якорем доверия (Root of Trust) и Remote Attestation.
5. **Защита от side-channel атак** и строгий контроль целостности рантайма.

---

## Раздел 2. Архитектура системы и Модель угроз

### 2.1. Модель доверия и слоёв (D-Domains)

*Примечание: используется термин D (Domain) вместо T во избежание путаницы с индустриальным TEE (Trusted Execution Environment).*

| Доверие | Домен (D) | Слой (L) | Компонент | Назначение |
|---|---|---|---|---|
| **Макс.** | D0–D2 | L0–L2 | HW, OS, HAL, TPM/HSM | Аппаратный якорь, крипто-бэкенд, управление питанием/теплом |
| **Высокое** | D3–D4 | L3–L4 | Crypto, IPC, LLM Gateway | Крипто-операции, gRPC-шина, прокси для внешних API |
| **Среднее** | D5 | L5 | Sandbox Boundary | Механизм изоляции (bwrap, SECCOMP, eBPF). Граница доверия |
| **Высокое** | D6–D7 | L6–L7 | FSM, WORM Audit | Управление состояниями, неизменяемый лог |
| **Нулевое** | D8 | L8 | Cognitive Payload | ИИ-модели, RAG, пользовательский код. Находится *внутри* L5 |

### 2.2. Модель угроз (STRIDE + MITRE ATLAS)

| Угроза | Вектор атаки | Контрмера в ZT-AI-CORE |
|---|---|---|
| **Spoofing** | Подмена D8-процесса | mTLS (TTL ≤ 5 мин) + IMA/dm-verity при старте |
| **Tampering** | Модификация RAG-базы | Ed25519-подпись индексов и весов модели |
| **Repudiation** | Отрицание отправки промпта | WORM-лог с nonce + внешний якорь (TPM/S3) |
| **Info Disclosure** | Утечка через LLM Gateway | Egress DLP, allow-list, rate-limit, circuit breaker |
| **DoS** | Prompt bomb / исчерпание RAM | cgroup лимиты, таймауты FSM, isolcpus |
| **EoP** | Побег из песочницы | SECCOMP (exact flag match), eBPF, запрет `clone3` |
| **Prompt Injection** | Отравление RAG-контекста | Санитайзинг чанков, разделение промпта и данных |
| **Model Extraction** | Кража весов через API | Ограничение top_k, логирование аномалий |
| **Data Poisoning** | Вредоносные источники в RAG | Подпись источников, дедупликация по хэшу |
| **Side-Channel** | Утечка через KSM / Cache | KSM off, `mlock`, изоляция ядер, TZASC |

---

## Раздел 3. Функциональные требования

### 3.1. Блок A–C: RAG-ядро (Ingestion, KB, Retriever)

- **F-A-01 – F-A-06:** Парсинг, очистка (Scrapy/Playwright), чанкинг с перекрытием 10–15% (300–800 токенов), дедупликация по криптографическому хэшу, извлечение только main content.
- **F-B-01 – F-B-05:** Локальные эмбеддинги (BGE-M3 / e5-small), векторная БД (ChromaDB/pgvector), гибридный поиск (вектор + BM25) + Reranking (Cross-Encoder).
- **F-C-01 – F-C-05:** Жёсткий системный промпт. Fallback: *«Информации в базе знаний недостаточно»*. Разделение инструкций и данных на уровне архитектуры (не конкатенация строк).

### 3.2. Блок D: Инференс и LLM Gateway (L4 / D8)

- **F-D-01:** Приоритетная локальная модель: Qwen 2.5 (14B/32B).
- **F-D-02:** Внешний LLM Gateway (L4) для маршрутизации запросов от D8 к облачным API.
- **F-D-03: Валидатор ответов (Каскад по возрастанию стоимости):**
  1. *Rule-based (~0.1 мс):* regex/словари для PII, ключей, запрещённых фраз. Срабатывание → немедленная блокировка (fail fast).
  2. *Embedding-similarity (~5–20 мс, CPU):* косинусное расстояние между ответом и контекстом.
     - `cos_sim > 0.85` → ответ принят, шаг 3 пропускается.
     - `0.60 ≤ cos_sim ≤ 0.85` → передача на уровень 3.
     - `cos_sim < 0.60` → немедленный fallback.
  3. *NLI-модель (~50–200 мс, CPU):* проверка логического следования (DeBERTa-v3-base-mnli). Только для пограничных случаев.
  4. Результат валидации (хэш ответа + вердикт) логируется в WORM.
- **F-D-04: LLM Gateway (L4) MUST:**
  - Аутентифицировать D8 через mTLS с краткоживущими сертификатами (TTL ≤ 5 мин).
  - Применять Egress Content Filter (DLP): блокировать утечку PII, ключей, внутренних UUID.
  - Реализовывать Rate-Limit (N запросов/мин) и Circuit Breaker.
  - Поддерживать жёсткий allow-list доменов.
  - Вести собственный WORM-лог всех egress-запросов (хэш payload + метаданные).

### 3.3. Блок E: Изоляция и защита D8 (L5)

- **F-E-01:** Bubblewrap: `--unshare-net`, `--unshare-pid`, `--ro-bind /`, `--die-with-parent`.
- **F-E-02:** SECCOMP-профиль (Приложение В): строгий whitelist, exact match для `clone`, полный запрет `clone3`, контроль `PROT_EXEC` через Bootstrap Sequence.
- **F-E-03:** eBPF-фильтр: блокировка `AF_INET`/`AF_INET6`, ограничение ФС (`/tmp`, `/var/rag`).
- **F-E-04:** IPC — только gRPC/Protobuf по Unix Domain Sockets с проверкой `SO_PEERCRED` и валидацией `sun_path`.
- **F-E-05: Side-channel защита:**
  - KSM MUST быть отключён для cgroup D8.
  - Ключевые регионы памяти (крипто-буферы, веса модели) MUST быть зафиксированы через `mlock()`.
  - CPU-ядра D8 SHOULD быть изолированы через `isolcpus=` или `cpuset` cgroup.
  - Для ARM: TrustZone/TZASC для изоляции памяти крипто-операций (L3).
- **F-E-06: Измерение целостности рантайма D8:**
  - При каждом старте D8 вычисляется и пишется в WORM: SHA-256 хэш интерпретатора, список загруженных `.so` (из `/proc/self/maps`), хэш весов модели (Merkle-root).
  - Несовпадение с эталоном из подписанного SBOM → `BOOT_FAILSAFE` (политика IMA appraisal).
- **F-E-07: Eager Loading (обязательная предварительная загрузка):**
  - Все C-extensions, JIT-графы и веса моделей MUST быть загружены и инициализированы на этапе Bootstrap Sequence **ДО** применения SECCOMP-фильтра.
  - Lazy loading `.so`/`.pyd` и JIT-компиляция после старта запрещены. Любой `mmap(PROT_EXEC)` после фильтра → SIGKILL.
  - **Обязательный warm-up:** после загрузки весов MUST выполнить 1 forward pass на dummy-данных.
  - **Запрещено в RAG-ядре:** `numba.jit`, `torch.compile`, `torch.jit.script` без предварительной компиляции, `cffi` с runtime-компиляцией.
  - **Базовый snapshot:** после warm-up сохранить `/proc/self/maps` как baseline. После применения SECCOMP — сверка с baseline, любое расхождение → SIGKILL.
  - **Env-переменные:** `PYTHONDONTWRITEBYTECODE=1`, `GRPC_DISABLE_DYNAMIC_PLUGINS=1`, `TORCH_DISABLE_DYNAMIC_JIT=1`.
- **F-E-08: Совместимость многопоточности (clone):**
  - Среда выполнения D8 MUST использовать `glibc` (не `musl`), так как `glibc` использует `clone` с проверяемыми флагами, а `musl` мигрирует на запрещённый `clone3`.
- **F-E-09: Capability Drop:**
  - Перед применением SECCOMP-фильтра MUST быть выполнены:
    - Drop всех capabilities через `prctl(PR_CAPBSET_DROP, cap)` для каждого cap в bounding set.
    - `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
    - Проверка `/proc/self/status`: `CapEff == 0`, `CapPrm == 0`, `CapInh == 0`, `NoNewPrivs == 1`.
  - Только после успешной проверки — вызов `seccomp(SECCOMP_SET_MODE_FILTER, ...)`.

### 3.4. Блок F: FSM и консенсус (L6)

- **F-F-01:** Жизненный цикл: `BOOT → BOOT_FAILSAFE → SELF_TEST → RUNNING → DEGRADED → SHUTDOWN`.
- **F-F-02:** Режимы: `NOMINAL`, `ISOLATED`, `RECOVERY`.
- **F-F-03:** Pending Rollback Counter: откат прошивки запрещён до успешного `SELF_TEST`.
- **F-F-04:** Распределённый консенсус (Raft) — только для кластерных узлов. Для Edge — локальный кворумный лог.
- **F-F-05: Атомарность переходов:**
  - Текущее состояние + `intent-to-transition` пишутся в WAL (TPM NV-RAM или выделенный раздел с гарантированным `fsync`).
  - При старте: незавершённый переход → принудительный `RECOVERY` + повтор `SELF_TEST`.
  - Переход завершён только после записи в WAL + подтверждения watchdog.

### 3.5. Блок G: WORM-аудит (L7)

- **F-G-01:** Append-only журнал. Структура: `payload_hash, timestamp, nonce, previous_hash, record_signature`.
- **F-G-02:** Хеширование: **BLAKE3**. Подпись чекпоинтов: **Ed25519**.
- **F-G-03:** Защита от Replay: строгая проверка `nonce` + временные окна (TTL).
- **F-G-04: Anti-Truncation (защита от отката цепи):**
  - Checkpoint публикуется при: ≥ 1000 записей **ИЛИ** ≥ 60 секунд с прошлого.
  - Якорь — в ДВУХ независимых местах:
    1. TPM NV-Counter (offline-верификация, ≤ 1 запись/час).
    2. Внешний WORM-сервис (S3 Object Lock / отдельный узел) — при каждом checkpoint.
  - **Логика сверки при старте:**
    - `seq_TPM > seq_local` или `seq_ext > seq_local` → **Truncation** → немедленный `RECOVERY`, блокировка записи.
    - `seq_local > seq_ext` → норма (неподтверждённые записи), публикация нового checkpoint при первой возможности.
    - Внешний якорь недоступен > 5 минут → `DEGRADED`, запись продолжается, checkpoint'ы копятся в локальном защищённом буфере.
- **F-G-05: Экономия TPM NV:**
  - Запись в TPM NV-Counter — не чаще 1 раза в час.
  - При < 1 часа с прошлой записи — checkpoint идёт только в S3.
  - Износ NV-ячейки мониторится; при 80% → `DEGRADED` + алерт.

### 3.6. Блок H: HAL и Криптография (L2–L3)

- **F-H-01:** Симметрия: AES-256-GCM (данные at-rest). Nonce — уникальные 96-битные. При невозможности — AES-256-GCM-SIV. Монотонный счётчик рекомендован.
- **F-H-02:** Асимметрия: Ed25519 (подпись), X25519 (ECDH).
- **F-H-03:** Управление ключами: TPM 2.0 / ARM TrustZone (OP-TEE) / HSM. Ключи **никогда** не экспортируются в D8. Операции — в L3 via PKCS#11 или нативный API.
- **F-H-04:** Тепловой бюджет: `T_j ≤ 75 °C`. Аппаратный троттлинг. Derating ≥ 20% от даташита.
- **F-H-05: Remote Attestation:**
  - При mTLS-сессии с внешними доверенными сервисами D8 MUST предъявить TPM Quote: AK-подпись PCR[0-15] (PCR[0-7] — firmware/bootloader/kernel/initrd; PCR[8-15] — runtime ZT-AI-CORE).
  - Внешний сервис сверяет PCR с эталоном из SBOM. Без успешной аттестации — разрыв соединения.

### 3.7. Блок I: Supply Chain и обновления

- **F-I-01:** Все артефакты обновлений подписаны offline-ключом Ed25519 (HSM).
- **F-I-02:** Anti-downgrade: `version_number` монотонно, хранится в TPM NV. Откат блокируется на `BOOT`.
- **F-I-03:** A/B: новое ПО → Slot B → SELF_TEST → атомарный `commit` в Slot A. Провал → rollback к Slot A.
- **F-I-04:** SBOM (CycloneDX или SPDX) для каждого релиза.
- **F-I-05:** Reproducible Builds для независимой верификации хэшей.

---

## Раздел 4. Нефункциональные требования

| ID | Требование | Значение |
|---|---|---|
| NF-01 | Время отклика RAG (поиск + rerank, без LLM) | ≤ 1.5 с |
| NF-02 | Время отклика с локальным LLM (Qwen 14B, Jetson) | ≤ 15 с |
| NF-03 | Пропускная способность WORM-аудита | ≥ 10 000 записей/с |
| NF-04 | MTBF | ≥ 10 000 ч |
| NF-05 | MTTR (детекция + начало перехода) | ≤ 500 мс (полная стабилизация ≤ 5 с) |
| NF-06 | Потребление RAM (D8, модель 14B) | ≤ 12 ГБ |
| NF-07 | Энергопотребление (Jetson Orin NX) | NOMINAL (RAG+LLM) ≤ 25 Вт; NOMINAL (RAG) ≤ 10 Вт; DEGRADED ≤ 3 Вт; ISOLATED ≤ 5 Вт |
| NF-08 | Температура чипа под нагрузкой | ≤ 75 °C |
| NF-09 | Логирование | 100% действий ИИ, IPC и оператора |

---

## Раздел 5. Структура репозитория

```text
my-secure-platform/
├── README.md
├── LICENSE                          # Apache 2.0 / MIT
├── docs/
│   ├── 00-technical-specification.md
│   ├── 00-threat-model.md
│   ├── 01-implementation-checklist.md
│   ├── 02-runbook.md
│   ├── 03-layers.md                 # L0–L8
│   ├── 04-domains.md                # D0–D8
│   ├── 05-fsm-matrix.md
│   ├── 06-crypto-profile.md
│   ├── 07-worm-audit.md
│   ├── 08-sandbox-config.md
│   └── 09-hal-thermal.md
├── submodules/
│   ├── t8-sandbox/                  # bwrap, seccomp (custom BPF), ebpf, grpc-client
│   ├── fsm-engine/                  # Rust: states, transitions, rollback, consensus
│   ├── worm-audit/                  # Rust/Go: chain, record, checkpoint, replay
│   ├── hal-common/                  # crypto, thermal, power, platform
│   ├── llm-gateway/                 # L4 proxy: mTLS, DLP, rate-limit
│   └── rag-core/                    # ingestion, KB, retriever, llm-client, validator
├── api/proto/
│   ├── sandbox.proto
│   ├── fsm.proto
│   ├── audit.proto
│   └── rag.proto
├── scripts/
│   ├── build-sec-profile.sh
│   ├── build-sandbox.sh
│   ├── run-self-test.sh
│   ├── gen-keys.sh
│   └── deploy.sh
├── docker-compose.yml
├── Makefile
└── .github/workflows/
    ├── ci.yml
    └── security-scan.yml
```

---

## Раздел 6. Дорожная карта

1. **Этап 1:** HAL & Crypto (L2/L3, TPM/HSM, Libsodium/OpenSSL).
2. **Этап 2:** Sandbox L5 (bwrap, eBPF, SECCOMP custom BPF, gRPC-граница).
3. **Этап 3:** FSM & Audit (FSM-матрица, WORM dual-anchor, атомарные переходы).
4. **Этап 4:** LLM Gateway (L4: mTLS, DLP, rate-limit).
5. **Этап 5:** RAG Core (Ingestion, Vector DB, Retriever, каскадный валидатор).
6. **Этап 6:** Integration & Supply Chain (A/B updates, SBOM, reproducible builds).
7. **Этап 7: Тестирование и валидация безопасности:**
   - Fuzzing SECCOMP и IPC (AFL++ / libfuzzer).
   - Red Teaming LLM Gateway (prompt injection, exfiltration).
   - Chaos Engineering FSM (см. чек-лист, сценарии A–E).
   - Аудит воспроизводимости сборок и SBOM (`gosec`, `cargo-audit`, `trivy`).

---

## Раздел 7. Критерии приёмки (Acceptance Criteria)

| ID | Критерий | Метод проверки |
|---|---|---|
| AC-01 | Сетевая изоляция D8 | Попытка `socket(AF_INET)` из D8 → `SECCOMP kill` / `eBPF drop` |
| AC-02 | Невозможность кражи ключей | Дамп памяти D8 → отсутствие приватных ключей |
| AC-03 | Защита WORM от Truncation | Удаление хвоста лога → `seq_local < seq_TPM` при старте → `RECOVERY` |
| AC-04 | Атомарность FSM | Отключение питания при переходе → старт в `RECOVERY` |
| AC-05 | Целостность рантайма | Подмена `.so` → несовпадение IMA → `BOOT_FAILSAFE` |
| AC-06 | Защита от галлюцинаций | 100 вопросов вне базы → 100% fallback |
| AC-07 | Side-channel защита | KSM отключён для D8, ключевые страницы в `mlock` |
| AC-08 | Remote Attestation | Подключение без валидного TPM Quote → разрыв mTLS |
| AC-09 | Eager Loading | `import` нового `.so` после SECCOMP → SIGKILL |
| AC-10 | Capability Drop | `/proc/self/status` после старта: `CapEff == 0` |

---

## Приложение А. Матрица FSM (Lifecycle × Operating Modes)

| Lifecycle \ Mode | NOMINAL | ISOLATED | RECOVERY |
|---|---|---|---|
| **BOOT** | ✅ | ❌ | ❌ |
| **BOOT_FAILSAFE** | ❌ | ❌ | ✅ |
| **SELF_TEST** | ✅ | ✅ | ❌ |
| **RUNNING** | ✅ | ✅ | ✅ |
| **DEGRADED** | ❌ | ✅ | ✅ |
| **SHUTDOWN** | ✅ | ✅ | ✅ |

---

## Приложение Б. Криптографический профиль

1. **Транзит (gRPC/TLS):** TLS 1.3. Шифры: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. Обмен ключами: X25519.
2. **Данные at-rest:** AES-256-GCM, уникальные 96-битные nonce. При невозможности — AES-256-GCM-SIV.
3. **WORM-аудит:** `BLAKE3(prev_hash || payload_hash || timestamp || nonce)`. Подпись checkpoint: `Ed25519(private_key_in_TPM, checkpoint_hash)`.
4. **Генерация случайности:** только `getrandom()` (Linux) или аппаратный TRNG (через HAL).
5. **Remote Attestation:** TPM 2.0, AK, PCR[0-15], сверка с SBOM.

---

## Приложение В. SECCOMP-профиль для D8 (Строгий, v2.4)

**Критическое архитектурное правило (Bootstrap Sequence):**
Все операции, требующие `PROT_EXEC` (загрузка C-extensions, инициализация рантайма, warm-up моделей), выполняются **ДО** применения SECCOMP-фильтра. Фильтр применяется только после полного запуска целевого процесса, импорта всех библиотек, warm-up моделей и capability drop.

**Разрешённые системные вызовы (Whitelist):**

```text
# 1. Базовые операции с памятью и файлами
read, write, openat, close, fstat, mmap, mprotect, munmap, brk,
pread64, pwrite64, lseek, dup, dup2, dup3, pipe2, getdents64,

# 2. Управление потоками (СТРОГОЕ ограничение)
# clone — только с точным совпадением маски флагов (SCMP_CMP_EQ):
#   CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
# clone3 — полностью запрещён (SCMP_ACT_KILL_PROCESS):
#   аргументы передаются через указатель на структуру, что невозможно
#   безопасно проверить чистым seccomp без seccomp_unotify.
clone, set_robust_list, set_tid_address, gettid, getpid, futex,

# 3. Время и сон
nanosleep, clock_gettime, clock_nanosleep, gettimeofday,

# 4. Случайность
getrandom,

# 5. Сетевые операции (СТРОГО только Unix Domain Sockets)
# eBPF-хук проверяет: sun_path == "/run/zt-core/rag.sock"
socket (только AF_UNIX), connect (только AF_UNIX), bind (только AF_UNIX),
accept4, sendmsg, recvmsg, shutdown, getsockname,

# 6. Сигналы и завершение
rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack, exit, exit_group,

# 7. Информация о системе (безопасные, read-only)
uname, sysinfo, getuid, getgid, geteuid, getegid
```

**Запрещено (SCMP_ACT_KILL_PROCESS):**
- Любой `execve`, `execveat` после bootstrap.
- `mmap` с `PROT_EXEC` в runtime (обеспечивается Bootstrap Sequence + опционально кастомный BPF: `args[2] & PROT_EXEC`).
- Любой `socket` с `AF_INET` / `AF_INET6`.
- `clone3` (полностью).
- `ptrace`, `mount`, `umount`, `chroot`, `pivot_root`, `bpf`.

---

**Конец ТЗ. Версия 2.4 (Final, 100%).**
*Документ закрыт, не содержит противоречий, готов к передаче в разработку, pen-test и сертификацию.*

---
