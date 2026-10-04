# Слои архитектуры ZT-AI-CORE (L0–L8)

**Источник:** ТЗ v2.4, Раздел 2.1. Документ нормативный: любая новая компонента обязана быть
закреплена за ровно одним слоем.

| Слой (L) | Домен (D) | Доверие | Компоненты | Назначение |
|---|---|---|---|---|
| **L0** | D0 | Максимальное | Аппаратная платформа (ARM64/x86_64/Jetson), TrustZone/TZASC | Физический якорь доверия, изоляция памяти крипто-операций |
| **L1** | D1 | Максимальное | Ядро Linux, dm-verity, IMA, cgroup v2, isolcpus | Целостность ОС, измерение рантайма, лимиты ресурсов |
| **L2** | D2 | Максимальное | HAL, TPM 2.0 / HSM / OP-TEE | Root of Trust, хранение ключей (never exportable), NV-Counter, PCR |
| **L3** | D3 | Высокое | Крипто-подсистема (Libsodium/OpenSSL 3.x, PKCS#11) | AES-256-GCM, Ed25519, X25519, BLAKE3, getrandom()/TRNG |
| **L4** | D4 | Высокое | gRPC/Protobuf-шина (UDS), **LLM Gateway** | Единственная легальная точка выхода наружу: mTLS, DLP, rate-limit, circuit breaker, allow-list |
| **L5** | D5 | Среднее | Sandbox Boundary: bwrap, SECCOMP (custom BPF), eBPF | Граница доверия. Механизм изоляции D8. Не доверяет содержимому, контролирует периметр |
| **L6** | D6 | Высокое | FSM-движок (детерминированный, WAL) | Управление жизненным циклом и режимами, атомарные переходы, Pending Rollback Counter |
| **L7** | D7 | Высокое | WORM-аудит (BLAKE3 hash-chain, Ed25519 checkpoint) | Неизменяемый журнал 100% событий, anti-truncation, dual-anchor (TPM NV + S3) |
| **L8** | D8 | **Нулевое** | Когнитивный payload: LLM (Qwen 2.5), RAG-ядро, пользовательский код | ИИ-нагрузка. Запущена **внутри** границы L5. Не имеет прямого доступа к сети, ФС хоста и ключам |

## Ключевые правила взаимодействия слоёв

1. **L8 → внешняя сеть:** только через L4 (LLM Gateway). Прямые `AF_INET`/`AF_INET6` сокеты
   в D8 запрещены на трёх уровнях: SECCOMP (kill), eBPF (drop), bwrap (`--unshare-net`).
2. **L8 → L6/L7:** только gRPC/Protobuf по Unix Domain Sockets с проверкой `SO_PEERCRED`
   и валидацией `sun_path` (`/run/zt-core/*.sock`).
3. **L8 → ключи:** никогда. Крипто-операции с приватными ключами выполняются в L2/L3
   (TPM/HSM/PKCS#11); в D8 экспортируются только публичные ключи.
4. **L5 не доверяет L8, но и не исполняет его код:** слой L5 — механизм (bwrap/SECCOMP/eBPF),
   политика задаётся L6 (FSM) и профилями из `submodules/t8-sandbox/`.
5. **Каждое пересечение границы L5** (IPC, egress, операторские команды) логируется в L7 (WORM).
6. **Сбой любого слоя L0–L4** обрабатывается FSM (L6): `DEGRADED`/`RECOVERY`/`BOOT_FAILSAFE`
   согласно матрице (см. `05-fsm-matrix.md`).

## Отображение слоёв на подмодули репозитория

| Слой | Подмодуль / артефакт |
|---|---|
| L2–L3 | `submodules/hal-common/` (crypto, thermal, power, platform, TPM-операции) |
| L4 | `submodules/llm-gateway/` |
| L5 | `submodules/t8-sandbox/` (bwrap, seccomp, ebpf, grpc-client) |
| L6 | `submodules/fsm-engine/` |
| L7 | `submodules/worm-audit/` |
| L8 | `submodules/rag-core/` (запускается через `t8-sandbox/bootstrap.py`) |
| Контракты | `api/proto/*.proto` |
