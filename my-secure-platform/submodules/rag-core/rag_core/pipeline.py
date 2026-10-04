"""RAG-пайплайн D8 (F-A…F-D): ingest → retrieve → изолированный промпт →
LLM → каскадный валидатор → fallback → WORM-аудит.

AC-06: вопросы вне базы знаний → 100% fallback
«Информации в базе знаний недостаточно».
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import AuditHook
from .config import RagConfig
from .ingestion.chunker import TextChunk, WordApproxCounter, chunk_text
from .ingestion.cleaner import sanitize_chunk
from .ingestion.dedup import DedupRegistry, hash_text
from .ingestion.parser import parse_document
from .kb.bm25 import Bm25Index
from .kb.signing import IndexSigner, IndexSignature
from .kb.store import (
    InMemoryVectorStore,
    StoredChunk,
    create_embedder,
)
from .llm_client import LlmError, create_llm_client
from .prompts.isolation import (
    FALLBACK_ANSWER,
    build_prompt,
    prompt_integrity_invariants,
)
from .retriever.hybrid import HybridRetriever, LexicalOverlapReranker, ScoredChunk
from .validator.cascade import CascadeValidator, ValidatorStage, VerdictCode
from .validator.nli import create_nli_validator
from .validator.similarity import SimilarityValidator


@dataclass
class IngestedDocReport:
    doc_id: str
    status: str           # ACCEPTED | DUPLICATE | PARSE_ERROR | REJECTED_POISON
    content_hash: str = ""
    chunks_created: int = 0
    detail: str = ""


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    reports: List[IngestedDocReport] = field(default_factory=list)
    audit_seq: Optional[int] = None


@dataclass
class RagAnswer:
    """Соответствует rag.proto:RagAnswer."""
    query_id: str
    answer: str
    decided_by: str
    verdict_code: str
    answer_hash: str
    audit_seq: Optional[int]
    is_fallback: bool
    model_id: str
    total_latency_ms: float
    cos_sim: float = 0.0
    nli_entailment: float = 0.0
    context_chunks: List[Dict[str, Any]] = field(default_factory=list)


class RagPipeline:
    def __init__(self, config: Optional[RagConfig] = None,
                 audit: Optional[AuditHook] = None,
                 llm_client: Optional[Any] = None,
                 index_signer: Optional[IndexSigner] = None):
        self.config = config or RagConfig()
        problems = self.config.validate()
        if problems:
            raise ValueError("конфигурация RAG невалидна: " + "; ".join(problems))
        self.store = InMemoryVectorStore()
        self.embedder = create_embedder(self.config.retrieval.embedder,
                                        self.config.retrieval.embed_dim)
        self.bm25 = Bm25Index()
        self.retriever = HybridRetriever(
            self.store, self.embedder, self.bm25,
            rrf_k=self.config.retrieval.rrf_k,
            reranker=LexicalOverlapReranker())
        self.dedup = DedupRegistry()
        self.similarity = SimilarityValidator(
            self.embedder,
            cos_accept=self.config.validator.cos_accept,
            cos_reject=self.config.validator.cos_reject)
        self.validator = CascadeValidator(
            self.similarity,
            create_nli_validator("lexical"),
            nli_entail_threshold=self.config.validator.nli_threshold)
        self.llm = llm_client or create_llm_client(
            self.config.llm.mode, self.config.llm.gateway_url,
            self.config.llm.local_url, self.config.llm.timeout_secs)
        self.audit = audit if audit is not None else AuditHook(
            socket_path=self.config.audit_socket,
            spool_path=self.config.audit_spool)
        self.signer = index_signer or IndexSigner(None)
        self.index_signature: Optional[IndexSignature] = None
        self._counter = WordApproxCounter()

    # ------------------------------------------------------------ Ingestion
    def ingest_text(self, doc_id: str, content: str | bytes,
                    source_uri: str = "", mime: str = "",
                    metadata: Optional[Dict[str, str]] = None) -> IngestedDocReport:
        parsed = parse_document(content, mime or None, source_uri)
        if not parsed.text.strip():
            return IngestedDocReport(doc_id, "PARSE_ERROR",
                                     detail="main content пуст")
        # Санитайзинг всего документа (Prompt Injection контрмера)
        sanitized = sanitize_chunk(parsed.text, strict=False)
        decision = self.dedup.check_document(doc_id, sanitized.text)
        if decision.is_duplicate and self.config.ingestion.dedup_by_hash:
            return IngestedDocReport(doc_id, "DUPLICATE",
                                     content_hash=decision.content_hash,
                                     detail=f"дубликат документа {decision.first_doc_id}")
        chunks = chunk_text(
            sanitized.text,
            min_tokens=self.config.ingestion.chunk_min_tokens,
            max_tokens=self.config.ingestion.chunk_max_tokens,
            hard_max_tokens=self.config.ingestion.chunk_hard_max,
            overlap_ratio=self.config.ingestion.overlap_ratio,
            counter=self._counter)
        created = 0
        poisoned = 0
        for ch in chunks:
            chunk_decision = self.dedup.check_chunk(ch.text)
            if chunk_decision.is_duplicate:
                continue
            per_chunk = sanitize_chunk(ch.text, strict=True)
            if per_chunk.suspicious:
                poisoned += 1
                continue
            chunk_id = f"{doc_id}#c{ch.ordinal}"
            self.store.upsert(StoredChunk(
                chunk_id=chunk_id, doc_id=doc_id, ordinal=ch.ordinal,
                text=per_chunk.text,
                content_hash=chunk_decision.content_hash,
                token_count=ch.token_count,
                overlap_tokens_prev=ch.overlap_tokens_prev,
                vector=self.embedder.embed(per_chunk.text),
                metadata=dict(metadata or {})))
            created += 1
        self.retriever.reindex_bm25()
        self.index_signature = self.signer.sign(self.store.all_chunks())
        status = "REJECTED_POISON" if (poisoned and created == 0) else "ACCEPTED"
        detail = f"chunks={created}" + (f", poisoned_rejected={poisoned}" if poisoned else "")
        self.audit.record("RECORD_KIND_INTEGRITY", {
            "event": "ingest", "doc_id": doc_id, "status": status,
            "content_hash": decision.content_hash, "chunks": created,
            "poisoned_rejected": poisoned, "source_uri": source_uri})
        return IngestedDocReport(doc_id, status, decision.content_hash,
                                 created, detail)

    def ingest_documents(self, documents: List[Dict[str, Any]]) -> IngestResult:
        result = IngestResult()
        for doc in documents:
            report = self.ingest_text(
                doc_id=str(doc.get("doc_id", "")) or f"doc-{time.time_ns()}",
                content=doc.get("content", ""),
                source_uri=str(doc.get("source_uri", "")),
                mime=str(doc.get("mime_type", "")),
                metadata=doc.get("metadata"))
            result.reports.append(report)
            if report.status == "ACCEPTED":
                result.accepted += 1
            elif report.status == "DUPLICATE":
                result.duplicates += 1
            else:
                result.rejected += 1
        return result

    # ---------------------------------------------------------------- Query
    def retrieve(self, question: str, top_k: Optional[int] = None) -> List[ScoredChunk]:
        cfg = self.config.retrieval
        res = self.retriever.retrieve(
            question,
            top_k=top_k or cfg.top_k,
            top_k_max=cfg.top_k_max,
            min_score=cfg.min_score)
        return res.scored

    def query(self, question: str, query_id: str = "") -> RagAnswer:
        started = time.monotonic()
        query_id = query_id or f"q-{time.time_ns()}"

        # WORM: промпт пользователя (NF-09: 100% действий ИИ)
        self.audit.record("RECORD_KIND_PROMPT",
                          {"query_id": query_id, "question": question},
                          subject="d8")

        scored = self.retrieve(question)
        if not scored:
            return self._fallback(query_id, VerdictCode.EMPTY_RETRIEVAL,
                                  ValidatorStage.FALLBACK, started, [],
                                  "retrieval пуст — вопроса нет в KB (AC-06)")

        context_pairs = [(sc.chunk.chunk_id, sc.chunk.text) for sc in scored]
        # Веса — ОТНОСИТЕЛЬНАЯ релевантность (лучший чанк = 1.0). Абсолютные
        # RRF/rerank-скоры (≈0.03) обнулили бы cos против абсолютных порогов
        # 0.85/0.60 (F-D-03) — нормализация обязательна.
        raw_weights = [max(sc.final_score, 0.0) for sc in scored]
        max_w = max(raw_weights) if raw_weights else 0.0
        weights = [(w / max_w) if max_w > 0 else 1.0 for w in raw_weights]
        prompt = build_prompt(question, context_pairs)
        invariants = prompt_integrity_invariants(prompt)
        if invariants:
            # нарушение изоляции промпта — ответ не генерируется
            return self._fallback(query_id, VerdictCode.INSUFFICIENT_CONTEXT,
                                  ValidatorStage.FALLBACK, started, scored,
                                  f"prompt isolation violation: {invariants}")

        try:
            llm_resp = self.llm.generate(prompt, [t for _, t in context_pairs])
        except LlmError as exc:
            return self._fallback(query_id, VerdictCode.INSUFFICIENT_CONTEXT,
                                  ValidatorStage.FALLBACK, started, scored,
                                  f"LLM недоступна: {exc}")

        trace = self.validator.validate(
            llm_resp.text, [t for _, t in context_pairs], weights)

        if trace.accepted:
            answer = llm_resp.text
            is_fallback = False
            code = trace.code
            decided = trace.decided_by
        else:
            answer = FALLBACK_ANSWER
            is_fallback = True
            code = trace.code if trace.code != VerdictCode.ACCEPTED \
                else VerdictCode.INSUFFICIENT_CONTEXT
            decided = ValidatorStage.FALLBACK

        answer_hash = hash_text(answer)
        # WORM: вердикт валидатора + хэш ответа (F-D-03 п.4)
        ok = self.audit.record("RECORD_KIND_VALIDATOR_VERDICT", {
            "query_id": query_id,
            "answer_hash": answer_hash,
            "decided_by": decided,
            "verdict_code": code,
            "cos_sim": trace.cos_sim,
            "nli_entailment": trace.nli_entailment,
            "rule_hits": trace.rule_hits,
            "nli_skipped": trace.nli_skipped,
            "rule_ms": round(trace.rule_ms, 3),
            "embed_ms": round(trace.embed_ms, 3),
            "nli_ms": round(trace.nli_ms, 3),
            "is_fallback": is_fallback,
        }, subject="d8")
        total_ms = (time.monotonic() - started) * 1000
        return RagAnswer(
            query_id=query_id, answer=answer, decided_by=decided,
            verdict_code=code, answer_hash=answer_hash,
            audit_seq=None, is_fallback=is_fallback,
            model_id=llm_resp.model_id, total_latency_ms=total_ms,
            cos_sim=trace.cos_sim, nli_entailment=trace.nli_entailment,
            context_chunks=[{
                "chunk_id": sc.chunk.chunk_id, "doc_id": sc.chunk.doc_id,
                "text": sc.chunk.text[:512], "rrf_score": round(sc.rrf_score, 6),
                "rerank_score": (round(sc.rerank_score, 6)
                                 if sc.rerank_score is not None else None),
                "final_rank": sc.final_rank,
            } for sc in scored],
        )

    def _fallback(self, query_id: str, code: str, stage: str,
                  started: float, scored: List[ScoredChunk],
                  detail: str) -> RagAnswer:
        answer = FALLBACK_ANSWER
        answer_hash = hash_text(answer)
        self.audit.record("RECORD_KIND_VALIDATOR_VERDICT", {
            "query_id": query_id, "answer_hash": answer_hash,
            "decided_by": stage, "verdict_code": code,
            "is_fallback": True, "detail": detail,
        }, subject="d8")
        return RagAnswer(
            query_id=query_id, answer=answer, decided_by=stage,
            verdict_code=code, answer_hash=answer_hash, audit_seq=None,
            is_fallback=True, model_id="fallback-policy",
            total_latency_ms=(time.monotonic() - started) * 1000,
            context_chunks=[{"chunk_id": sc.chunk.chunk_id,
                             "doc_id": sc.chunk.doc_id,
                             "final_rank": sc.final_rank} for sc in scored],
        )

    # ------------------------------------------------------------ persistence
    def save_kb(self, directory: Optional[str] = None) -> Path:
        import json

        kb_dir = Path(directory or self.config.kb_dir)
        kb_dir.mkdir(parents=True, exist_ok=True)
        chunks = [{
            "chunk_id": c.chunk_id, "doc_id": c.doc_id, "ordinal": c.ordinal,
            "text": c.text, "content_hash": c.content_hash,
            "token_count": c.token_count,
            "overlap_tokens_prev": c.overlap_tokens_prev,
            "vector": c.vector, "metadata": c.metadata,
        } for c in self.store.all_chunks()]
        (kb_dir / "chunks.json").write_text(
            json.dumps(chunks, ensure_ascii=False), encoding="utf-8")
        (kb_dir / "dedup.json").write_text(
            json.dumps(self.dedup.state(), ensure_ascii=False), encoding="utf-8")
        if self.index_signature:
            (kb_dir / "index.sig").write_text(json.dumps({
                "index_digest": self.index_signature.index_digest,
                "signature_hex": self.index_signature.signature_hex,
                "public_key_hex": self.index_signature.public_key_hex,
                "algorithm": self.index_signature.algorithm,
            }), encoding="utf-8")
        return kb_dir

    def load_kb(self, directory: Optional[str] = None) -> int:
        import json

        kb_dir = Path(directory or self.config.kb_dir)
        chunks_path = kb_dir / "chunks.json"
        if not chunks_path.exists():
            return 0
        chunks = json.loads(chunks_path.read_text(encoding="utf-8"))
        for c in chunks:
            self.store.upsert(StoredChunk(
                chunk_id=c["chunk_id"], doc_id=c["doc_id"], ordinal=c["ordinal"],
                text=c["text"], content_hash=c["content_hash"],
                token_count=c["token_count"],
                overlap_tokens_prev=c.get("overlap_tokens_prev", 0),
                vector=c.get("vector"), metadata=c.get("metadata", {})))
        dedup_path = kb_dir / "dedup.json"
        if dedup_path.exists():
            self.dedup.load_state(json.loads(dedup_path.read_text(encoding="utf-8")))
        self.retriever.reindex_bm25()
        return len(chunks)

    # ----------------------------------------------------------------- health
    def health(self) -> Dict[str, Any]:
        from .models import is_warmed_up, warmup_report
        chunks = self.store.all_chunks()
        tokens = [c.token_count for c in chunks]
        return {
            "healthy": True,
            "kb_documents": len({c.doc_id for c in chunks}),
            "kb_chunks": len(chunks),
            "avg_chunk_tokens": (sum(tokens) / len(tokens)) if tokens else 0.0,
            "embedder_id": self.embedder.name,
            "models_warmed_up": is_warmed_up(),
            "warmup_report": warmup_report(),
            "index_signed": bool(self.index_signature
                                 and self.index_signature.signature_hex),
        }
