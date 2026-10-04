# Домены доверия ZT-AI-CORE (D0–D8)

**Источник:** ТЗ v2.4, Раздел 2.1.

> **Примечание по терминологии:** используется термин **D (Domain)** вместо T, чтобы избежать
> путаницы с индустриальным TEE (Trusted Execution Environment).

## Таблица доменов

| Домен | Уровень доверия | Слой | Компонент | Граница ответственности |
|---|---|---|---|---|
| **D0** | Максимальное | L0 | Hardware (CPU, TZASC, TRNG) | Физический якорь; изоляция памяти крипто-операций (ARM TrustZone) |
| **D1** | Максимальное | L1 | OS Kernel (dm-verity, IMA, cgroup v2) | Целостность загрузки и рантайма; лимиты ресурсов D8 |
| **D2** | Максимальное | L2 | TPM 2.0 / HSM / HAL | Root of Trust: EK/AK, PCR[0-15], NV-Counter, неизвлекаемые ключи |
| **D3** | Высокое | L3 | Crypto-подсистема | Реализация крипто-профиля (Приложение Б ТЗ); ключи никогда не покидают D2/D3 |
| **D4** | Высокое | L4 | IPC-шина + LLM Gateway | mTLS (TTL ≤ 5 мин), Egress DLP, rate-limit, circuit breaker, allow-list доменов |
| **D5** | Среднее | L5 | Sandbox Boundary | Механизм изоляции: bwrap + SECCOMP + eBPF. Доверяет только политике, не payload |
| **D6** | Высокое | L6 | FSM-движок | Детерминированные состояния/режимы, WAL-атомарность, Pending Rollback Counter |
| **D7** | Высокое | L7 | WORM-аудит | Append-only hash-chain (BLAKE3), Ed25519-чекпоинты, dual-anchor anti-truncation |
| **D8** | **Нулевое** | L8 | Cognitive Payload (LLM, RAG, код пользователя) | Всё, что запущено внутри L5. Считается потенциально скомпрометированным |

## Правила Zero-Trust для D8

D8 — домен **нулевого доверия**. Архитектура исходит из того, что процесс(ы) D8 могут быть
полностью контролируемы атакующим (prompt injection → RCE). Поэтому:

1. **Ни одного привилегированного syscall:** capabilities сброшены (`CapEff == 0`),
   `NoNewPrivs == 1`, SECCOMP-whitelist (Приложение В ТЗ), `clone3` запрещён полностью.
2. **Ни одного сетевого сокета кроме AF_UNIX** с валидацией `sun_path` (`/run/zt-core/rag.sock`).
3. **Ни одной записи на диск хоста кроме** `/tmp` и `/var/rag` (eBPF-контроль ФС).
4. **Никакого lazy-кода после старта:** Eager Loading + warm-up ДО SECCOMP; любой
   `mmap(PROT_EXEC)` после фильтра → SIGKILL; сверка `/proc/self/maps` с baseline.
5. **Никаких ключей в памяти D8** (AC-02): приватные ключи — только в D2 (TPM/HSM);
   операции подписи — через L3/L4.
6. **Каждое действие D8 фиксируется в D7** (WORM): промпты, ответы, egress, IPC, вердикты
   валидатора — 100% покрытие (NF-09).
7. **Внешний трафик D8 — только через D4** (LLM Gateway) с TPM Quote (Remote Attestation,
   F-H-05): без валидной аттестации соединение разрывается (AC-08).

## Каналы между доменами

```text
D8 (L8, внутри L5)
 │  AF_UNIX gRPC (/run/zt-core/rag.sock, SO_PEERCRED)      ── контролируется D5 (L5)
 ├──> D7 WORM-аудит (append-only; dual-anchor: TPM NV + S3 Object Lock)
 ├──> D6 FSM (запросы переходов; watchdog; WAL)
 └──> D4 LLM Gateway ──mTLS+TPM Quote──> Внешние LLM API (allow-list)
D2 (TPM/HSM) <── D3 (crypto-операции) <── D4/D6/D7 (подписи, аттестация, якоря)
D0/D1 ── аппаратная и ядерная основа всех слоёв
```

## Эскалация при компрометации домена

| Скомпрометирован | Реакция FSM (D6) |
|---|---|
| D8 | Изоляция штатна (Zero-Trust by design): SECCOMP/eBPF kill, circuit breaker в D4, полная фиксация в D7 |
| D4 | `DEGRADED`, egress блокируется, локальный Qwen продолжает работу (Chaos-сценарий E) |
| D5 | `BOOT_FAILSAFE` → `RECOVERY` (нарушение границы доверия) |
| D6/D7 | Немедленный `RECOVERY`, блокировка записи, форензика (runbook §2) |
| D2 | Полный останов: Root of Trust утерян, `SHUTDOWN` с эскалацией в CISO |
