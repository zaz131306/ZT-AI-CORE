"""Точка входа: ``python3 -m llm_gateway.main``."""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .config import GatewayConfig
from .server import run_gateway


def build_config(args: argparse.Namespace) -> GatewayConfig:
    cfg = GatewayConfig.from_env()
    if args.listen:
        cfg.listen = args.listen
    if args.port:
        cfg.port = args.port
    if args.cert:
        cfg.tls_cert = args.cert
    if args.key:
        cfg.tls_key = args.key
    if args.ca:
        cfg.tls_ca = args.ca
    if args.allowlist:
        cfg.allowlist = [x.strip() for x in args.allowlist.split(",") if x.strip()]
    if args.rate_limit:
        cfg.rate_limit_per_min = args.rate_limit
    if args.audit_socket:
        cfg.audit_socket = args.audit_socket
    if args.mock_upstream:
        cfg.mock_upstream = True
    if args.tls_min:
        cfg.tls_min_version = args.tls_min
    return cfg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m llm_gateway.main",
        description="ZT-AI-CORE LLM Gateway (L4): mTLS, Egress DLP, rate-limit, "
                    "circuit breaker (F-D-04)")
    parser.add_argument("--listen", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--cert", default=None, help="серверный сертификат (PEM)")
    parser.add_argument("--key", default=None, help="серверный ключ (PEM)")
    parser.add_argument("--ca", default=None, help="CA для проверки клиентов (mTLS)")
    parser.add_argument("--allowlist", default=None,
                        help="домены egress через запятую (перекрывает env)")
    parser.add_argument("--rate-limit", type=int, default=None,
                        help="запросов в минуту на клиента")
    parser.add_argument("--audit-socket", default=None,
                        help="UDS worm-audit (/run/zt-core/audit.sock)")
    parser.add_argument("--mock-upstream", action="store_true",
                        help="детерминированный мок апстрима (dev/chaos)")
    parser.add_argument("--tls-min", default=None, choices=["1.2", "1.3"],
                        help="минимальная версия TLS (по умолчанию 1.3, Приложение Б)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr)

    cfg = build_config(args)
    problems = cfg.validate()
    if problems:
        for p in problems:
            print(f"llm-gateway: CONFIG ERROR: {p}", file=sys.stderr)
        return 2
    try:
        asyncio.run(run_gateway(cfg))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
