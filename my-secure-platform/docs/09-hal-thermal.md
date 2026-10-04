# HAL: тепловой и энергетический бюджет (L0–L2)

**Источник:** ТЗ v2.4, F-H-04, NF-06…NF-08, runbook §6.
Реализация: `submodules/hal-common/` (Rust: thermal, power, platform, crypto, tpm).

## 1. Тепловой бюджет (F-H-04, NF-08)

| Параметр | Значение |
|---|---|
| Предельная температура кристалла | **T_j ≤ 75 °C** |
| Derating от даташита | **≥ 20%** |
| Источник телеметрии | sysfs `thermal_zone*` / Jetson `tegrastats` / BMC |
| Аппаратный троттлинг | Включён всегда (не полагаться только на ПО) |

Политика реакции:

```text
T_j < 60 °C            → NOMINAL (полная нагрузка)
60 °C ≤ T_j < 70 °C    → предупреждение, планировщик снижает batch/top_k
70 °C ≤ T_j ≤ 75 °C    → DEGRADED (дерейтинг ≥ 20%: снижение частот/нагрузки инференса)
T_j > 75 °C            → принудительный троттлинг + ISOLATED; повтор > 3 раз/мин → SHUTDOWN
```

Метрика `zt_d8_cpu_temp > 75 °C` → **Critical** (runbook §6).

## 2. Энергетический бюджет (NF-07, Jetson Orin NX)

| Режим | Бюджет |
|---|---|
| NOMINAL (RAG + LLM) | **≤ 25 Вт** |
| NOMINAL (только RAG) | **≤ 10 Вт** |
| ISOLATED | **≤ 5 Вт** |
| DEGRADED | **≤ 3 Вт** |

Контроль: `hal_common::power::PowerBudget::for_mode(mode)` — источник истины для
планировщика нагрузки; превышение бюджета → дерейтинг, затем FSM `DEGRADED`.

## 3. Память (NF-06)

- D8 с моделью 14B: **≤ 12 ГБ RAM** (cgroup `memory.max` жёстко).
- Веса модели: `mlock()` после загрузки (F-E-05), учёт в baseline `/proc/self/maps`.

## 4. Платформы (Раздел 0 ТЗ)

| Платформа | Особенности HAL |
|---|---|
| ARM64 (серверный) | TZASC для изоляции памяти крипто-операций L3; OP-TEE как Root of Trust |
| x86_64 | TPM 2.0 (fTPM/dTPM); isolcpus; KSM off |
| Nvidia Jetson (Orin/Xavier) | tegrastats-телеметрия, nvpmodel-бюджеты, TPМ-эмуляция через fTPM |

Обязательное требование: **glibc** (не musl) — F-E-08 (корректный `clone` без `clone3`).
Проверка в `hal_common::platform::runtime_is_glibc()`.

## 5. Целевые показатели надёжности

| Показатель | Значение |
|---|---|
| MTBF | ≥ 10 000 ч (NF-04) |
| MTTR: детекция + начало перехода | ≤ 500 мс (NF-05) |
| Полная стабилизация | ≤ 5 с (NF-05) |

## 6. TPM-операции HAL (интерфейс `TpmOps`)

- `nv_counter_read/increment` — якорь WORM (износ ≤ 1 записи/час; мониторинг wear, алерт 80%).
- `pcr_extend(8..15)` — измерение рантайма ZT-AI-CORE при старте.
- `quote(pcrs 0..15, ak)` — Remote Attestation для LLM Gateway (F-H-05).
- `sign_ed25519(handle, digest)` — подпись чекпоинтов WORM без экспорта ключа.

Реализации: `MockTpm` (детерминированный, для тестов/CI) и `LinuxTpm` (tss2/tpm2-tools —
подключается на целевом железе; в CI не требуется).
