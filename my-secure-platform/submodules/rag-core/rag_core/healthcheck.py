"""Healthcheck rag-core для docker/systemd: UDS-запрос Health."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m rag_core.healthcheck")
    parser.add_argument("--socket", default=os.environ.get("ZT_RAG_SOCKET",
                                                            "/run/zt-core/rag.sock"))
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        sock.connect(args.socket)
        request = {"jsonrpc": "zt-uds/1.0", "method": "Health",
                   "params": {}, "id": 1}
        sock.sendall(json.dumps(request).encode() + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        sock.close()
        response = json.loads(buf.split(b"\n", 1)[0])
        if "result" in response and response["result"].get("healthy"):
            print("healthcheck: rag-core OK",
                  f"chunks={response['result'].get('kb_chunks')}")
            return 0
        print(f"healthcheck: некорректный ответ: {response!r}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"healthcheck: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
