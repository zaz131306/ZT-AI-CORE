# Fuzzing контуров (Этап 7 ТЗ v2.4)

## Состав

| Файл | Назначение |
|---|---|
| `run_fuzz.py` | Встроенная детерминированная fuzz-кампания (запускается `make fuzz`): мутации JSON-контрактов rag.proto/audit.proto/fsm.proto + реальные Rust UDS-серверы + компилятор/симулятор SECCOMP |
| `afl/ztseccomp_harness.py` | AFL++/afl-python harness: профиль SECCOMP из stdin → compile+simulate (цель — компилятор BPF) |
| `afl/rag_dispatch_harness.py` | AFL++ harness: JSON-запрос из stdin → RagServer.handle |

## Запуск

```bash
# Встроенная кампания (всегда доступна, детерминированный seed):
make fuzz                      # 5 000 итераций
make fuzz-heavy                # 200 000 итераций (или AFL++ при наличии)

# AFL++ (при установке afl++):
afl-fuzz -i seeds/profiles -o findings -- \
    python3 tests/fuzz/afl/ztseccomp_harness.py
afl-fuzz -i seeds/requests -o findings-rag -- \
    python3 tests/fuzz/afl/rag_dispatch_harness.py
```

## Инварианты кампании

1. **U DS-сервисы не умирают** на любой враждебный ввод: ответ с `error`
   либо закрытие соединения; гибель процесса = crash = баг.
2. **Компилятор SECCOMP** на любой мутант-профиль отвечает либо валидной
   BPF-программой (проходящей симулятор), либо контролируемым `ProfileError`.
3. **Симулятор** на любую программу/вход — `SimResult` или `SimulationError`
   (никаких бесконечных циклов: лимит 100k шагов).
4. **RagServer.dispatch** — только JSON-ответ (`result`/`error`), любые
   значения полей (NaN, 2^128, вложенные структуры, не-UTF8) не приводят к
   неперехваченным исключениям.

## Chaos-сценарии (чек-лист §5, A–E)

Сценарии A–E автоматизированы на уровне юнит/интеграционных тестов
подмодулей (см. `worm-audit/src/service.rs::tests` — chaos C/D;
`llm-gateway/tests/test_server_e2e.py::test_circuit_breaker_opens_and_recovers`
— chaos E; `fsm-engine` — деградация по anchor down). Сетевые инъекции
(tc/netem, DNS-blackhole) выполняются на стенде по runbook.
