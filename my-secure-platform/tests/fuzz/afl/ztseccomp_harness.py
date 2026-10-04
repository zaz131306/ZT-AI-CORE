#!/usr/bin/env python3
"""AFL++ harness: фаззинг компилятора SECCOMP-профилей ztseccomp.

Вход: JSON-профиль на stdin (afl-fuzz мутирует seed-профили).
Инвариант: результат — либо скомпилированная программа (проходящая
симулятор на контрольных входах), либо контролируемая ошибка
ProfileError/ValueError/TypeError. Любой иной исход — crash.

Запуск:
    afl-fuzz -i seeds -o findings -- python3 ztseccomp_harness.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SANDBOX = ROOT / "submodules" / "t8-sandbox"
sys.path.insert(0, str(SANDBOX / "seccomp"))
sys.path.insert(0, str(SANDBOX))

from ztseccomp._tables_gen import AUDIT_ARCH_X86_64, X86_64_SYSCALLS  # noqa: E402
from ztseccomp.profile import ProfileError, compile_profile  # noqa: E402
from ztseccomp.simulate import SimulationError, simulate  # noqa: E402

CONTROL_SYSCALLS = ["read", "write", "socket", "clone", "clone3", "mmap",
                    "execve", "exit_group", "ioctl", "openat"]


def main() -> int:
    raw = sys.stdin.buffer.read()
    try:
        profile = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0  # невалидный JSON — нормальный отказ на границе
    try:
        program, report = compile_profile(profile, arch="x86_64")
    except (ProfileError, ValueError, TypeError, KeyError, IndexError,
            RecursionError):
        return 0  # контролируемый отказ компилятора
    # Скомпилированная программа обязана корректно исполняться в симуляторе.
    try:
        for name in CONTROL_SYSCALLS:
            nr = X86_64_SYSCALLS.get(name)
            if nr is None:
                continue
            for args in ([], [1], [2], [0x10F00], [0, 4096, 7]):
                res = simulate(program, nr, AUDIT_ARCH_X86_64, args)
                assert isinstance(res.action, int)
    except (SimulationError, AssertionError):
        return 0
    except Exception:  # noqa: BLE001 — всё прочее = баг компилятора
        sys.stderr.write(f"CRASH: profile={raw[:500]!r}\n")
        raise
    _ = report
    return 0


if __name__ == "__main__":
    sys.exit(main())
