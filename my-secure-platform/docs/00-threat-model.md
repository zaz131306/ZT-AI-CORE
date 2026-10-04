# Модель угроз ZT-AI-CORE (STRIDE + MITRE ATLAS)

| Угроза | Вектор атаки | Контрмера |
|---|---|---|
| **Spoofing** | Подмена D8-процесса | mTLS (TTL ≤ 5 мин) + IMA/dm-verity + TPM Quote |
| **Tampering** | Модификация RAG-базы | Ed25519-подпись индексов и весов + IMA appraisal |
| **Repudiation** | Отрицание отправки промпта | WORM-лог с nonce + dual-anchor (TPM NV + S3) |
| **Info Disclosure** | Утечка через LLM Gateway | Egress DLP, allow-list, rate-limit, circuit breaker |
| **DoS** | Prompt bomb / исчерпание RAM | cgroup лимиты, таймауты FSM, isolcpus |
| **EoP** | Побег из песочницы | SECCOMP (exact flag match), eBPF, запрет `clone3`, capability drop |
| **Prompt Injection (ATLAS)** | Внедрение инструкций через RAG | Санитайзинг чанков, разделение промпта и данных |
| **Model Extraction (ATLAS)** | Кража весов через API | Ограничение top_k, логирование аномалий, rate-limit |
| **Data Poisoning (ATLAS)** | Вредоносные источники | Подпись источников, дедупликация по криптографическому хэшу |
| **Side-Channel** | Утечка через KSM / Cache | KSM off, `mlock`, isolcpus, TZASC |
| **Supply Chain** | Подмена обновления | Ed25519 offline-подпись, anti-downgrade (TPM NV), SBOM, reproducible builds |

---
