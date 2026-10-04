"""CLI компилятора SECCOMP-профиля: ``python3 -m ztseccomp.compile``.

Пример (scripts/build-sec-profile.sh)::

    python3 -m ztseccomp.compile \
        --profile bwrap/seccomp_profile.json \
        --arch x86_64 \
        --out build/seccomp_strict_x86_64.bpf \
        --report build/seccomp_strict_x86_64.report.json \
        --disasm
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .apply import pack_filter_to_file, program_blake3
from .bpf import disassemble
from .profile import ProfileError, compile_profile, load_profile, native_arch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m ztseccomp.compile",
        description="Компиляция JSON-профиля SECCOMP ZT-AI-CORE в classic BPF "
                    "(Приложение В ТЗ v2.4)")
    parser.add_argument("--profile", required=True, type=Path,
                        help="путь к seccomp_profile.json")
    parser.add_argument("--arch", default=None, choices=["x86_64", "aarch64"],
                        help="целевая архитектура (default: нативная)")
    parser.add_argument("--out", type=Path, default=None,
                        help="файл артефакта BPF (заголовок ZTSB + sock_filter[])")
    parser.add_argument("--report", type=Path, default=None,
                        help="JSON-отчёт компиляции")
    parser.add_argument("--disasm", action="store_true",
                        help="напечатать дизассемблированную программу")
    parser.add_argument("--validate-only", action="store_true",
                        help="только валидировать профиль (без компиляции)")
    args = parser.parse_args(argv)

    try:
        data = load_profile(args.profile)
    except (OSError, json.JSONDecodeError, ProfileError) as exc:
        print(f"ERROR: invalid profile {args.profile}: {exc}", file=sys.stderr)
        return 2

    if args.validate_only:
        meta = data.get("meta", {})
        print(f"OK: profile valid ({args.profile}); "
              f"defaultAction={data.get('defaultAction')}, "
              f"entries={len(data.get('syscalls', []))}, "
              f"meta.version={meta.get('version', '?')}")
        return 0

    arch = args.arch or native_arch()
    try:
        program, report = compile_profile(data, arch=arch)
    except ProfileError as exc:
        print(f"ERROR: compile failed: {exc}", file=sys.stderr)
        return 3

    digest = program_blake3(program)
    print(f"compiled: arch={arch} insns={report.instruction_count} "
          f"bytes={len(program)} blake3={digest}")
    if report.skipped_names:
        print(f"note: skipped (отсутствуют в ABI {arch}): "
              f"{', '.join(report.skipped_names)}")
    for note in report.notes:
        print(f"note: {note}")

    if args.out:
        pack_filter_to_file(program, args.out)
        print(f"artifact: {args.out}")
    if args.report:
        payload = report.as_dict()
        payload["program_blake3"] = digest
        payload["profile_path"] = str(args.profile)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                               encoding="utf-8")
        print(f"report: {args.report}")
    if args.disasm:
        for line in disassemble(program):
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
