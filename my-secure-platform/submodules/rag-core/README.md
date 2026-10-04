# rag-core — когнитивное ядро D8 (L8)

RAG-пайплайн нулевого доверия (ТЗ v2.4, Разделы 3.1–3.2, F-A…F-D).
Запускается ВНУТРИ песочницы L5 через `t8-sandbox/bootstrap.py`.

## Конвейер

```text
Ingestion (F-A)                     Query (F-B/C/D)
────────────────                    ───────────────
parse (html/md/txt,                 question
 main-content only)                     │
  │ sanitize (анти-инъекции:        retrieve: vector ⊕ BM25 → RRF
  │  invisible-chars, role-маркеры,      → rerank → top_k ≤ 8 (anti-extraction)
  │  injection-паттерны)                 │
  │ chunk 300–800 токенов           build_prompt: ИЗОЛИРОВАННЫЙ конверт
  │  overlap 10–15%                 (system=policy, user=DATA-envelope)
  │ dedup по BLAKE3                      │
  ▼                                 LLM (local Qwen 2.5 / gateway / extractive)
KB: InMemory | ChromaDB | pgvector       │
 + BM25-индекс + Ed25519-подпись    КАСКАДНЫЙ ВАЛИДАТОР (F-D-03):
   индекса (anti-Tampering)          1. rules (~0.1 мс)  → BLOCK fail-fast
                                     2. cos-sim (~5–20 мс) → >0.85 ACCEPT (NLI пропущен)
                                                             <0.60 FALLBACK
                                     3. NLI DeBERTa (~50–200 мс, пограничные)
                                     4. вердикт+хэш ответа → WORM
```

**AC-06**: вопросы вне базы → 100% fallback
«Информации в базе знаний недостаточно» (тест на 100 вопросов).

## Модули

| Модуль | Назначение |
|---|---|
| `ingestion/parser.py` | main-content extraction (stdlib html.parser) |
| `ingestion/cleaner.py` | санитайзер: invisible/role-маркеры/injection-паттерны |
| `ingestion/chunker.py` | чанкинг 300–800 токенов, overlap 10–15%, sentence-boundary |
| `ingestion/dedup.py` | дедупликация документов/чанков по BLAKE3 |
| `kb/store.py` | HashingEmbedder (dev) / BGE-M3 / e5-small (prod), InMemory/Chroma/pgvector |
| `kb/bm25.py` | Okapi BM25 |
| `kb/signing.py` | Ed25519-подпись индекса (Tampering-контрмера) |
| `retriever/hybrid.py` | vector⊕BM25 → RRF → CrossEncoder/lexical rerank, NF-01 |
| `prompts/isolation.py` | жёсткий системный промпт + DATA-конверт (F-C-05) |
| `validator/` | rules / similarity (0.85/0.60) / NLI / cascade |
| `llm_client.py` | Qwen local / L4 gateway / offline-extractive |
| `audit.py` | WORM-хук: PROMPT + VALIDATOR_VERDICT (NF-09, F-D-03 п.4) |
| `models.py` | `warmup_all()` — warm-up хук bootstrap (F-E-07) |
| `server.py` | UDS-сервер `rag.proto` + SO_PEERCRED + sun_path-валидация |

## Запуск

```bash
PYTHONPATH=. python3 -m pytest -q tests        # 44 теста (включая AC-06)
python3 -m rag_core.server --socket /run/zt-core/rag.sock --kb /var/rag/kb
```

Прод-зависимости (`pip install .[prod]`): sentence-transformers (BGE-M3,
CrossEncoder, DeBERTa-MNLI), chromadb, blake3, cryptography — все импорты
выполняются EAGER на Шаге 3 Bootstrap Sequence (F-E-07); после применения
SECCOMP lazy-загрузка невозможна (mmap PROT_EXEC → SIGKILL).
