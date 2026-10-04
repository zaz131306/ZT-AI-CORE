"""UDS-сервер RAG-ядра (rag.proto, контракт /run/zt-core/rag.sock, F-E-04).

Методы: Ingest, Retrieve, Query, ValidateAnswer, Health, GetKbStats.
Серверная сторона проверяет SO_PEERCRED каждого соединения (uid allow-list
ZT_IPC_ALLOWED_UIDS) и валидирует sun_path сокета.

Запуск:  python3 -m rag_core.server --socket /run/zt-core/rag.sock
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .config import RagConfig
from .pipeline import RagPipeline

SUN_PATH_MAX = 108
DEFAULT_SOCKET = "/run/zt-core/rag.sock"


class PeerRejectedError(RuntimeError):
    pass


def validate_socket_path(path: str, socket_dir: str = "/run/zt-core") -> str:
    """Валидация sun_path серверного сокета (F-E-04)."""
    real = os.path.realpath(path)
    dir_real = os.path.realpath(socket_dir)
    if not real.startswith(dir_real + os.sep):
        raise PeerRejectedError(f"socket вне {socket_dir}: {path!r}")
    if not real.endswith(".sock"):
        raise PeerRejectedError(f"socket обязан оканчиваться на .sock: {path!r}")
    if len(path.encode("utf-8")) >= SUN_PATH_MAX:
        raise PeerRejectedError("sun_path длиннее лимита")
    return real


def check_peercred(conn: socket.socket, allowed_uids: tuple[int, ...]) -> tuple[int, int, int]:
    """SO_PEERCRED: (pid, uid, gid) клиента + проверка allow-list."""
    SO_PEERCRED = 17
    SOL_SOCKET = 1
    data = conn.getsockopt(SOL_SOCKET, SO_PEERCRED, struct.calcsize("iii"))
    pid, uid, gid = struct.unpack("iii", data)
    if uid not in allowed_uids:
        raise PeerRejectedError(f"uid {uid} не в allow-list {allowed_uids}")
    return pid, uid, gid


class RagServer:
    def __init__(self, pipeline: RagPipeline, allowed_uids: tuple[int, ...] = (0,)):
        self.pipeline = pipeline
        self.allowed_uids = allowed_uids
        self._listener: Optional[socket.socket] = None
        self._stop = threading.Event()

    # ------------------------------------------------------------ dispatch
    def handle(self, request: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if not isinstance(request, dict):
                raise ValueError(
                    f"запрос обязан быть JSON-объектом, получен {type(request).__name__}")
            method = str(request.get("method", ""))
            params = request.get("params") or {}
            if not isinstance(params, dict):
                raise ValueError("params обязан быть объектом")
            result = self.dispatch(method, params)
            return {"jsonrpc": "zt-uds/1.0", "id": request.get("id"),
                    "result": result}
        except Exception as exc:  # noqa: BLE001 — изоляция ошибок на границе IPC
            rid = request.get("id") if isinstance(request, dict) else None
            return {"jsonrpc": "zt-uds/1.0", "id": rid,
                    "error": f"{type(exc).__name__}: {exc}"}

    def dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "Ingest":
            documents = params.get("documents") or []
            if params.get("document"):
                documents = [params["document"]]
            result = self.pipeline.ingest_documents(documents)
            return {
                "accepted": result.accepted,
                "duplicates": result.duplicates,
                "rejected": result.rejected,
                "reports": [r.__dict__ for r in result.reports],
            }
        if method == "Retrieve":
            scored = self.pipeline.retrieve(
                str(params.get("question", "")),
                top_k=int(params.get("top_k", 0)) or None)
            return {"chunks": [{
                "chunk_id": sc.chunk.chunk_id, "doc_id": sc.chunk.doc_id,
                "text": sc.chunk.text, "vector_score": round(sc.vector_score, 6),
                "bm25_score": round(sc.bm25_score, 6),
                "rrf_score": round(sc.rrf_score, 6),
                "rerank_score": (round(sc.rerank_score, 6)
                                 if sc.rerank_score is not None else None),
                "final_rank": sc.final_rank} for sc in scored]}
        if method == "Query":
            answer = self.pipeline.query(
                str(params.get("question", "")),
                query_id=str(params.get("query_id", "")))
            return answer.__dict__
        if method == "ValidateAnswer":
            trace = self.pipeline.validator.validate(
                str(params.get("answer", "")),
                [str(c) for c in (params.get("context") or [])])
            return {
                "decided_by": trace.decided_by, "code": trace.code,
                "cos_sim": trace.cos_sim, "nli_entailment": trace.nli_entailment,
                "rule_hits": trace.rule_hits, "nli_skipped": trace.nli_skipped,
                "rule_ms": round(trace.rule_ms, 4),
                "embed_ms": round(trace.embed_ms, 4),
                "nli_ms": round(trace.nli_ms, 4),
                "accepted": trace.accepted,
            }
        if method == "Health":
            return self.pipeline.health()
        if method == "GetKbStats":
            chunks = self.pipeline.store.all_chunks()
            tokens = [c.token_count for c in chunks]
            sig = self.pipeline.index_signature
            return {
                "documents": len({c.doc_id for c in chunks}),
                "chunks": len(chunks),
                "vectors": sum(1 for c in chunks if c.vector),
                "index_signature": (sig.signature_hex if sig else None),
                "dedup_skipped": self.pipeline.dedup.skipped_duplicates,
                "avg_chunk_tokens": (sum(tokens) / len(tokens)) if tokens else 0.0,
            }
        raise ValueError(f"unknown method: {method}")

    # -------------------------------------------------------------- socket
    def serve(self, socket_path: str, socket_dir: str = "") -> None:
        # По умолчанию каталог сокета = родительский каталог socket_path
        # (в prod фиксируется /run/zt-core через параметр).
        directory = socket_dir or str(Path(socket_path).resolve().parent)
        path = validate_socket_path(socket_path, socket_dir=directory)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(path):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(16)
        os.chmod(path, 0o660)
        self._listener = listener
        print(f"[rag-core] serving on {path}", file=sys.stderr, flush=True)
        while not self._stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,),
                             daemon=True).start()
        try:
            listener.close()
            os.unlink(path)
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(60.0)
            check_peercred(conn, self.allowed_uids)
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        request = json.loads(line)
                    except json.JSONDecodeError as exc:
                        response = {"jsonrpc": "zt-uds/1.0",
                                    "error": f"bad json: {exc}"}
                    else:
                        response = self.handle(request)
                    conn.sendall(
                        json.dumps(response, ensure_ascii=False,
                                   separators=(",", ":")).encode("utf-8") + b"\n")
        except PeerRejectedError as exc:
            print(f"[rag-core] peer rejected: {exc}", file=sys.stderr, flush=True)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m rag_core.server",
                                     description="RAG-ядро ZT-AI-CORE (L8/D8)")
    parser.add_argument("--socket", default=os.environ.get("ZT_RAG_SOCKET", DEFAULT_SOCKET))
    parser.add_argument("--kb", default="", help="каталог персистентности KB")
    parser.add_argument("--audit-socket", default="")
    parser.add_argument("--gateway", default="")
    parser.add_argument("--allowed-uids", default="0",
                        help="UID allow-list для SO_PEERCRED (через запятую)")
    args = parser.parse_args(argv)

    config = RagConfig()
    if args.kb:
        config.kb_dir = args.kb
    if args.audit_socket:
        config.audit_socket = args.audit_socket
    if args.gateway:
        config.llm.gateway_url = args.gateway
        if config.llm.mode == "extractive":
            config.llm.mode = "gateway"  # явный gateway включает L4-маршрут
    pipeline = RagPipeline(config)
    loaded = pipeline.load_kb()
    if loaded:
        print(f"[rag-core] KB загружена: {loaded} чанков", file=sys.stderr)

    allowed_uids = tuple(int(x) for x in args.allowed_uids.split(",") if x.strip())
    server = RagServer(pipeline, allowed_uids=allowed_uids)

    import signal

    def _term(signum, frame):
        server.stop()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    server.serve(args.socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
