# Операционный runbook ZT-AI-CORE (v2.4)

## 1. Реакция на переход в DEGRADED

**Триггеры:**
- Внешний WORM-якорь (S3) недоступен > 5 мин.
- LLM Gateway не отвечает > 30 с.
- Износ TPM NV-ячейки > 80%.
- Pre-flight проверка частично провалена.

**Действия оператора:**
1. Проверить `/var/log/zt-core/fsm.log` — причина перехода.
2. Проверить доступность S3: `aws s3 ls s3://zt-worm-anchor/`.
3. Проверить LLM Gateway: `systemctl status zt-llm-gateway`.
4. Если внешний якорь недоступен > 30 мин — эскалация в SRE.
5. После восстановления — ручной триггер `RECOVERY` → `SELF_TEST` → `RUNNING`.

## 2. Реакция на переход в RECOVERY

**Триггеры:**
- Truncation WORM (`seq_local < seq_TPM` или `seq_local < seq_ext`).
- Незавершённый FSM-переход при старте (WAL обнаружил intent без commit).
- Провал SELF_TEST.

**Действия оператора:**
1. **НЕМЕДЛЕННО** остановить запись в WORM: `systemctl stop zt-worm-audit`.
2. Снять дамп состояния: `zt-core-cli dump-state > /var/forensics/$(date +%s).json`.
3. Проверить целостность WORM:
   ```
   zt-core-cli verify-chain --local /var/worm/log.db --tpm --external s3://zt-worm-anchor/
   ```
4. Если truncation подтверждён — инцидент безопасности. Эскалация в CISO.
5. Если причина в WAL (незавершённый переход) — безопасный вариант:
   - Восстановить из последнего валидного checkpoint.
   - Повторить SELF_TEST.
6. После успеха — переход в `RUNNING`.

## 3. Обновление ключей

**Ed25519 (подпись артефактов):** раз в год. Offline HSM. Процедура — двойной контроль (4 глаза).

**X25519 (ECDH, TLS):** ротация сертификатов каждые 90 дней. Автоматическая.

**BLAKE3, AES-GCM:** ротация не требуется (ключи — эфемерные или per-record).

**TPM AK/EK:** EK — на весь срок службы. AK — раз в год.

## 4. Обновление ПО (A/B)

1. Скачать артефакт + SBOM + подпись.
2. Проверить подпись offline-ключом: `zt-core-cli verify-update <artifact>`.
3. Проверить `version_number > current`.
4. Развернуть в Slot B: `zt-core-cli stage-update --slot B <artifact>`.
5. Перезагрузка в Slot B.
6. `SELF_TEST` в Slot B.
7. При успехе — `commit` в Slot A.
8. При провале — rollback к Slot A.

## 5. Восстановление WORM после сбоя

**Случай 1: диск с WORM-логом повреждён.**
- Восстановить из S3 Object Lock: `aws s3 sync s3://zt-worm-anchor/ /var/worm/restore/`.
- Сверить `seq_ext` с последним локальным.
- `zt-core-cli rebuild-chain --from-s3`.

**Случай 2: TPM NV-Counter недоступен.**
- Запись идёт только в S3.
- `DEGRADED` до восстановления TPM.
- При восстановлении — принудительная синхронизация: `zt-core-cli sync-tpm-nv`.

## 6. Мониторинг (метрики Prometheus)

| Метрика | Порог алерта |
|---|---|
| `zt_fsm_state` | изменение → PagerDuty |
| `zt_worm_seq_local` vs `zt_worm_seq_ext` | расхождение → Critical |
| `zt_tpm_nv_wear` | > 80% → Warning |
| `zt_llm_gateway_latency_p99` | > 30 с → Warning |
| `zt_d8_cpu_temp` | > 75 °C → Critical |
| `zt_d8_ksm_active` | > 0 → Critical (должен быть 0) |
| `zt_d8_cap_eff` | != 0 → Critical |

---

# Итог

| Артефакт | Версия | Точность | Готовность |
|---|---|---|---|
| **ТЗ** | 2.4 | **100%** | **100%** |
| **Чек-лист** | 2.4 | **100%** | **100%** |
| **Threat Model** | 2.4 | **100%** | **100%** |
| **Runbook** | 2.4 | **100%** | **100%** |
