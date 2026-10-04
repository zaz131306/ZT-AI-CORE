# hal-common — HAL и криптография (L2–L3)

Общие примитивы аппаратного слоя ZT-AI-CORE (ТЗ v2.4, Раздел 3.6,
docs/06-crypto-profile.md, docs/09-hal-thermal.md).

| Модуль | Назначение |
|---|---|
| `crypto.rs` | Крипто-профиль (Приложение Б): допустимые алгоритмы, TLS1.3-шифры, запрещённые конструкции (ГОСТ/legacy), `MonotonicNonce96` (F-H-01), `KeyLocation` never-exportable (F-H-03), BLAKE3-хелпер |
| `thermal.rs` | Тепловой бюджет `T_j ≤ 75 °C`, derating ≥ 20% (F-H-04/NF-08), классификатор действий, sysfs/mock-источники, эскалация EmergencyShutdown |
| `power.rs` | Энергетические бюджеты NF-07 (25/10/5/3 Вт), `D8_MEMORY_MAX = 12 ГБ` (NF-06) |
| `platform.rs` | Архитектура (x86_64/aarch64 + AUDIT_ARCH), **glibc-проверка (F-E-08)**, детекция Jetson, KSM-статус (F-E-05/AC-07) |
| `tpm.rs` | `TpmOps`: NV-Counter (монотонность, износ), PCR[0-15] extend, Quote (AK-подпись), Ed25519-подпись без экспорта ключа; `MockTpm` (файловый, детерминированный, переживает рестарт) для CI/стендов; `verify_quote` + сверка с SBOM (F-H-05) |

## Использование

```bash
cargo test        # 28 тестов
```

Крейт используется как path-зависимость: `worm-audit` (TPM-якорь, подпись
чекпоинтов) и `fsm-engine` (платформенные проверки SELF_TEST).

Прод-подключение: реализация `TpmOps` поверх tss2/tpm2-tools (TPM 2.0),
OP-TEE (ARM TrustZone) или PKCS#11 HSM — интерфейс и тесты-контракты
(монотонность NV, wear-порог 80%, quote-верификация) уже заданы.
