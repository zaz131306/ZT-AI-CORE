"""Healthcheck гейтвея для docker/systemd: TLS-handshake + GET /healthz.

``python3 -m llm_gateway.healthcheck --port 8443 [--ca ...] [--cert ... --key ...]
                                      [--plain-tcp]``
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys

from .config import GatewayConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m llm_gateway.healthcheck")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca", default=None)
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--plain-tcp", action="store_true",
                        help="только TCP-connect (без TLS-валидации)")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)

    cfg = GatewayConfig.from_env()
    ca = args.ca or cfg.tls_ca
    cert = args.cert or (cfg.tls_cert if args.cert else None)

    try:
        if args.plain_tcp:
            with socket.create_connection((args.host, args.port),
                                          timeout=args.timeout):
                print("healthcheck: TCP connect OK")
                return 0
        from .mtls import build_client_context
        ctx = build_client_context(ca, certfile=cert, keyfile=args.key or cert,
                                   server_hostname_check=False)
        with socket.create_connection((args.host, args.port),
                                      timeout=args.timeout) as sock:
            with ctx.wrap_socket(sock) as tls:
                tls.sendall(
                    b"GET /healthz HTTP/1.1\r\n"
                    b"Host: localhost\r\nConnection: close\r\n\r\n")
                data = tls.recv(4096)
        if data.startswith(b"HTTP/1.1 200"):
            print("healthcheck: TLS + /healthz OK")
            return 0
        print(f"healthcheck: неожиданный ответ: {data[:80]!r}", file=sys.stderr)
        return 1
    except (OSError, ssl.SSLError) as exc:
        print(f"healthcheck: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
