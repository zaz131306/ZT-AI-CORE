#!/usr/bin/env python3
"""ZT-AI-CORE: генератор таблиц номеров syscall для SECCOMP BPF-компилятора.

Парсит заголовки ядра Linux:
  * x86_64 : /usr/include/x86_64-linux-gnu/asm/unistd_64.h
  * aarch64: /usr/include/asm-generic/unistd.h (asm-generic таблица, Jetson/ARM64)

и порождает `ztseccomp/_tables_gen.py` с таблицами для whitelist Приложения В ТЗ
(+ расширенный dev-набор). Запуск: python3 tools/gen_syscall_tables.py [out.py]

ВНИМАНИЕ: таблицы должны регенерироваться только из заголовков ядра — ручное
редактирование запрещено (риск рассинхрона номеров = обход SECCOMP).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

X86_64_HEADER = Path("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")
GENERIC_HEADER = Path("/usr/include/asm-generic/unistd.h")

# Whitelist Приложения В ТЗ (строгий профиль) + явные запреты.
STRICT_SYSCALLS = [
    # 1. Базовые операции с памятью и файлами
    "read", "write", "openat", "close", "fstat", "mmap", "mprotect", "munmap",
    "brk", "pread64", "pwrite64", "lseek", "dup", "dup2", "dup3", "pipe2",
    "getdents64",
    # 2. Управление потоками (clone — только exact flag match; clone3 — запрет)
    "clone", "set_robust_list", "set_tid_address", "gettid", "getpid", "futex",
    # 3. Время и сон
    "nanosleep", "clock_gettime", "clock_nanosleep", "gettimeofday",
    # 4. Случайность
    "getrandom",
    # 5. Сеть — СТРОГО Unix Domain Sockets
    "socket", "connect", "bind", "accept4", "sendmsg", "recvmsg", "shutdown",
    "getsockname",
    # 6. Сигналы и завершение
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
    "exit", "exit_group",
    # 7. Информация о системе (read-only)
    "uname", "sysinfo", "getuid", "getgid", "geteuid", "getegid",
]

# Явно запрещённые (SCMP_ACT_KILL_PROCESS) — должны присутствовать в таблицах
# для генерации явных kill-правил.
BANNED_SYSCALLS = [
    "clone3", "execve", "execveat", "ptrace", "mount", "umount2", "chroot",
    "pivot_root", "bpf", "keyctl", "add_key", "request_key", "kexec_load",
    "init_module", "finit_module", "delete_module", "perf_event_open",
    "process_vm_readv", "process_vm_writev", "setns", "unshare", "userfaultfd",
]

# Расширенный dev-набор: то, что реально нужно glibc/CPython после bootstrap
# (документированное отклонение для dev-контура; в prod — только STRICT).
EXTENDED_EXTRA = [
    "ioctl", "fcntl", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "poll", "ppoll", "pselect6", "newfstatat", "statx", "readlinkat",
    "prlimit64", "rseq", "madvise", "mremap", "sched_yield", "sched_getaffinity",
    "getcwd", "faccessat2", "fsync", "fdatasync", "flock", "umask",
    "clock_getres", "eventfd2", "memfd_create", "socketpair", "getsockopt",
    "setsockopt", "getpeername", "sendto", "recvfrom", "readv", "writev",
    "kill", "tgkill", "tkill", "arch_prctl", "getppid", "gettid",
]

DEFINE_RE = re.compile(r"^\s*#define\s+(__NR3264_|__NR_)(\w+)\s+(.+?)\s*(?:/\*.*)?$")


def parse_header(path: Path) -> dict[str, int]:
    """Парсит unistd-заголовок в словарь {имя: номер}, разрешая алиасы."""
    raw: dict[str, str] = {}
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = DEFINE_RE.match(line)
        if not m:
            continue
        prefix, name, value = m.group(1), m.group(2), m.group(3)
        value = value.split("/*")[0].strip()
        raw[prefix + name] = value
        if prefix == "__NR_":
            raw.setdefault("__NR3264_" + name, value)

    def resolve(name: str, depth: int = 0) -> int | None:
        if depth > 8:
            return None
        val = raw.get("__NR_" + name) or raw.get("__NR3264_" + name)
        if val is None:
            return None
        if re.fullmatch(r"\d+", val):
            return int(val)
        # алиас вида `#define __NR_foo __NR3264_foo` — resolving the DIRECT link
        alias = val.strip()
        if alias.startswith("__NR3264_") or alias.startswith("__NR_"):
            target = raw.get(alias)
            if target is not None and re.fullmatch(r"\d+", target.strip()):
                return int(target.strip())
            # otherwise, resolve by the name without the prefix (avoiding self-reference)
            base = alias.split("_")[-1]
            if base != name:
                return resolve(base, depth + 1)
            return None
        mnum = re.search(r"(\d+)", alias)
        return int(mnum.group(1)) if mnum else None

    out: dict[str, int] = {}
    for key in list(raw):
        if key.startswith("__NR3264_"):
            name = key[len("__NR3264_"):]
        elif key.startswith("__NR_"):
            name = key[len("__NR_"):]
        else:
            continue
        if name in ("syscalls",):   # __NR_syscalls — счётчик, не syscall
            continue
        num = resolve(name)
        if num is not None and name not in out:
            out[name] = num
    return out


def pick(table: dict[str, int], names: list[str]) -> dict[str, int]:
    picked = {}
    for n in names:
        if n in table:
            picked[n] = table[n]
    return dict(sorted(picked.items(), key=lambda kv: kv[1]))


def missing(table: dict[str, int], names: list[str]) -> list[str]:
    return [n for n in names if n not in table]


def main() -> int:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parent.parent / "submodules/t8-sandbox/seccomp/ztseccomp/_tables_gen.py"

    if not X86_64_HEADER.exists() or not GENERIC_HEADER.exists():
        print(f"ERROR: kernel headers not found ({X86_64_HEADER}, {GENERIC_HEADER}).\n"
              "Install linux-libc-dev (Debian/Ubuntu) and re-run.", file=sys.stderr)
        return 1

    x86 = parse_header(X86_64_HEADER)
    arm = parse_header(GENERIC_HEADER)

    # Контроль: все имена whitelist Приложения В и бан-листа должны разрешаться
    # хотя бы для x86_64 (dup2/gettimeofday — x86-специфика проверяется отдельно).
    names_all = STRICT_SYSCALLS + BANNED_SYSCALLS + EXTENDED_EXTRA
    x86_miss = set(missing(x86, names_all))
    if x86_miss:
        print(f"WARN: x86_64 missing: {sorted(x86_miss)}", file=sys.stderr)
    arm_expected_missing = {"dup2", "poll", "epoll_wait", "arch_prctl"}
    arm_miss = set(missing(arm, names_all)) - arm_expected_missing
    if arm_miss:
        print(f"WARN: aarch64 missing: {sorted(arm_miss)}", file=sys.stderr)

    header = '''"""АВТОМАТИЧЕСКИ СГЕНЕРИРОВАНО tools/gen_syscall_tables.py — НЕ РЕДАКТИРОВАТЬ.

Полные таблицы номеров syscall из заголовков ядра Linux:
  x86_64 : /usr/include/x86_64-linux-gnu/asm/unistd_64.h
  aarch64: /usr/include/asm-generic/unistd.h (asm-generic ABI)

Отсутствие имени в таблице архитектуры допустимо, если syscall не входит
в ABI этой архитектуры (например, dup2/poll/epoll_wait отсутствуют на
aarch64 — используются dup3/ppoll/epoll_pwait). Компилятор BPF пропускает
такие имена с предупреждением в отчёте.
"""

# AUDIT_ARCH-константы (include/uapi/linux/audit.h)
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

'''
    x86_sorted = dict(sorted(x86.items(), key=lambda kv: kv[1]))
    arm_sorted = dict(sorted(arm.items(), key=lambda kv: kv[1]))
    body = "X86_64_SYSCALLS: dict[str, int] = " + repr(x86_sorted) + "\n\n"
    body += "AARCH64_SYSCALLS: dict[str, int] = " + repr(arm_sorted) + "\n\n"
    body += ("SYSCALL_TABLES: dict[str, dict[str, int]] = {\n"
             '    "x86_64": X86_64_SYSCALLS,\n'
             '    "aarch64": AARCH64_SYSCALLS,\n'
             "}\n")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(header + body, encoding="utf-8")
    print(f"generated {out_path} "
          f"(x86_64: {len(x86_sorted)} syscalls, aarch64: {len(arm_sorted)} syscalls)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
