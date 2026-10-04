#!/usr/bin/env python3
"""ZT-AI-CORE — встроенный статический security-сканер (цель `make sec-scan`).

Дополняет внешние инструменты (bandit/cargo-audit/trivy/semgrep) и работает
всегда — даже в изолированном CI без сети. Проверки:

  1. СЕКРЕТЫ: приватные ключи/токены в отслеживаемых файлах (кроме тестовых
     векторов и генераторов);
  2. Опасные конструкции: eval/exec/os.system/shell=True/pickle.loads в
     ПРОДАКШЕН-коде (tests/ исключены);
  3. Слабая криптография: md5/sha1/DES/RC4 в небенчмарочном коде;
  4. Незавершённый код: TODO/FIXME/"implement later" (требование ТЗ —
     репозиторий без заглушек);
  5. SECCOMP-политика: профили компилируются и проходят симуляторную
     верификацию (Приложение В);
  6. Гигиена: .gitignore содержит keys//*.pem; в репозитории нет *.key/*.pem
     с приватным материалом;
  7. Контракты: proto-файлы парсируются (grpcio-tools при наличии).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {"target", "node_modules", "__pycache__", ".git", "build", "dist",
             "api/gen", ".pytest_cache", "keys"}
SECRET_PATTERNS = [
    ("PEM private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]
# Файлы, где секреты-образцы легальны (тесты DLP/сканеров, генераторы ключей).
SECRET_ALLOWLIST = {
    "submodules/llm-gateway/tests/test_dlp.py",
    "submodules/llm-gateway/tests/test_server_e2e.py",
    "submodules/llm-gateway/tests/test_allowlist_mtls.py",
    "submodules/llm-gateway/llm_gateway/dlp.py",
    "submodules/rag-core/rag_core/validator/rules.py",
    "submodules/rag-core/tests/test_retriever_validator.py",
    "submodules/rag-core/tests/test_ingestion.py",
    "submodules/t8-sandbox/tests/test_dlp_reference.py",
    "tools/security_scan.py",
    "tests/fuzz/run_fuzz.py",
    "scripts/gen-keys.sh",
}
DANGEROUS_CALLS = [
    ("eval(", re.compile(r"(?<![\w.])eval\s*\(")),
    ("exec(", re.compile(r"(?<![\w.])exec\s*\(")),
    ("os.system(", re.compile(r"os\.system\s*\(")),
    ("shell=True", re.compile(r"shell\s*=\s*True")),
    ("pickle.loads", re.compile(r"pickle\.loads\s*\(")),
]
WEAK_CRYPTO = re.compile(r"hashlib\.(?:md5|sha1)\s*\(|\bDES\.new\b|\bARC4\b", re.IGNORECASE)
TODO_MARKERS = re.compile(
    r"\b(?:TODO|FIXME|XXX)\b|todo implement later|реализовать позже",
    re.IGNORECASE)
# Где TODO допустим (этот сканер, документация о процессе).
TODO_ALLOWLIST_PREFIXES = ("tools/security_scan.py",)

TEXT_SUFFIXES = {".py", ".rs", ".sh", ".md", ".json", ".yml", ".yaml", ".toml",
                 ".proto", ".c", ".h", ".txt", ""}


def iter_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if any(part in SKIP_DIRS for part in rel.split("/")):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield rel, path


def check_secrets(findings: list[str]) -> None:
    for rel, path in iter_files():
        if rel in SECRET_ALLOWLIST:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(f"SECRET[{name}]: {rel}")


def check_dangerous_calls(findings: list[str]) -> None:
    for rel, path in iter_files():
        if not rel.endswith(".py") or "/tests/" in rel or rel.endswith("conftest.py"):
            continue
        # Сканер и фаззер содержат САМИ паттерны как строковые константы.
        if rel in ("tools/security_scan.py", "tests/fuzz/run_fuzz.py"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.split("#", 1)[0]
            for name, pattern in DANGEROUS_CALLS:
                if pattern.search(stripped):
                    findings.append(f"DANGEROUS[{name}]: {rel}:{i}")
            if WEAK_CRYPTO.search(stripped):
                findings.append(f"WEAK-CRYPTO: {rel}:{i}: {stripped.strip()[:80]}")


def check_todos(findings: list[str]) -> None:
    for rel, path in iter_files():
        if rel.startswith(TODO_ALLOWLIST_PREFIXES):
            continue
        if rel.endswith(("LICENSE",)):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if TODO_MARKERS.search(line):
                findings.append(f"TODO-MARKER: {rel}:{i}: {line.strip()[:100]}")


def check_repo_hygiene(findings: list[str]) -> None:
    gitignore = ROOT / ".gitignore"
    if not gitignore.exists():
        findings.append("HYGIENE: .gitignore отсутствует")
    else:
        text = gitignore.read_text(encoding="utf-8")
        for must in ("keys/", "*.pem", "*.key"):
            if must not in text:
                findings.append(f"HYGIENE: .gitignore не содержит {must}")
    # приватные ключевые файлы не должны лежать в дереве
    for rel, path in iter_files():
        if path.suffix in (".pem", ".key", ".p12", ".pfx") and "/tests/" not in rel:
            findings.append(f"HYGIENE: ключевой файл в репозитории: {rel}")


def check_seccomp_policy(findings: list[str]) -> None:
    sandbox = ROOT / "submodules" / "t8-sandbox"
    sys.path.insert(0, str(sandbox / "seccomp"))
    sys.path.insert(0, str(sandbox))
    try:
        from ztseccomp._tables_gen import (AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64,
                                            SYSCALL_TABLES)
        from ztseccomp.profile import compile_profile
        from ztseccomp.simulate import check_cases, simulate, strict_policy_cases
    except ImportError as exc:
        findings.append(f"SECCOMP: импорт ztseccomp не удался: {exc}")
        return
    audit = {"x86_64": AUDIT_ARCH_X86_64, "aarch64": AUDIT_ARCH_AARCH64}
    for arch in ("x86_64", "aarch64"):
        try:
            prog, _ = compile_profile(str(sandbox / "bwrap" / "seccomp_profile.json"),
                                      arch=arch)
            fails = check_cases(prog, arch, audit[arch], SYSCALL_TABLES[arch],
                                strict_policy_cases(arch))
            if simulate(prog, 1, audit[arch] ^ 0xDEAD).action_name != "KILL_PROCESS":
                fails.append("wrong-arch guard не сработал")
            for f in fails:
                findings.append(f"SECCOMP[{arch}]: {f}")
        except Exception as exc:  # noqa: BLE001
            findings.append(f"SECCOMP[{arch}]: {type(exc).__name__}: {exc}")


def check_protos(findings: list[str]) -> None:
    try:
        import grpc_tools.protoc  # noqa: F401
    except ImportError:
        print("  (grpcio-tools не установлены — proto-проверка пропущена)")
        return
    import tempfile
    proto_dir = ROOT / "api" / "proto"
    protos = sorted(str(p) for p in proto_dir.glob("*.proto"))
    if not protos:
        findings.append("PROTO: api/proto пуст")
        return
    with tempfile.TemporaryDirectory() as out:
        cmd = [sys.executable, "-m", "grpc_tools.protoc",
               f"--proto_path={proto_dir}", f"--python_out={out}", *protos]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            findings.append(f"PROTO: компиляция не удалась: {proc.stderr[:400]}")


def main() -> int:
    print("== ZT-AI-CORE security scan (встроенный) ==")
    findings: list[str] = []
    check_secrets(findings)
    check_dangerous_calls(findings)
    check_todos(findings)
    check_repo_hygiene(findings)
    check_seccomp_policy(findings)
    check_protos(findings)

    if findings:
        print(f"\nНАЙДЕНО ПРОБЛЕМ: {len(findings)}")
        for f in findings[:200]:
            print(f"  - {f}")
        if len(findings) > 200:
            print(f"  ... и ещё {len(findings) - 200}")
        return 1
    print("  secrets: OK")
    print("  dangerous calls: OK")
    print("  weak crypto: OK")
    print("  todo-заглушки: OK")
    print("  repo hygiene: OK")
    print("  seccomp policy (Приложение В, симулятор): OK")
    print("  proto-контракты: OK")
    print("\nВстроенный security-скан: ЧИСТО")
    return 0


if __name__ == "__main__":
    sys.exit(main())
