"""Симулятор classic BPF для офлайн-верификации SECCOMP-политики.

Исполняет скомпилированную программу sock_filter[] против синтетических
``seccomp_data`` (nr, arch, args) БЕЗ запуска в ядре. Назначение:
  * юнит-тесты и fuzzing политики (tests/, tests/fuzz);
  * приёмка профиля в scripts/build-sec-profile.sh (policy check);
  * отладка компилятора (ловит класс багов «алиасинг аккумулятор↔nr»,
    недостижимый для выборочных ядерных тестов).

Поддерживаемый набор инструкций — ровно тот, который порождает
:mod:`ztseccomp.profile`: LD ABS W, ALU AND K, JMP JEQ/JGT/JSET/JA, RET K.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

INSN = struct.Struct("<HBBI")

# Классы/опкоды (дублируют bpf.py, чтобы симулятор не зависел от порядка импорта)
_CLS_LD = 0x00
_CLS_ALU = 0x04
_CLS_JMP = 0x05
_CLS_RET = 0x06

_LD_ABS_W = 0x20
_ALU_AND_K = 0x50
_JMP_JA = 0x00
_JMP_JEQ = 0x10
_JMP_JGT = 0x20
_JMP_JSET = 0x40

SECCOMP_DATA_SIZE = 64  # int nr; u32 arch; u64 ip; u64 args[6]
MAX_STEPS = 100_000

ACTION_NAMES = {
    0x7FFF0000: "ALLOW",
    0x80000000: "KILL_PROCESS",
    0x00000000: "KILL_THREAD",
    0x00030000: "TRAP",
    0x7FFC0000: "LOG",
}


class SimulationError(RuntimeError):
    """Программа некорректна (неподдерживаемая инструкция, цикл, выход за границы)."""


@dataclass(frozen=True)
class SimResult:
    action: int          # полное значение SECCOMP_RET_*
    steps: int

    @property
    def action_name(self) -> str:
        base = self.action & 0xFFFF0000
        if base in ACTION_NAMES:
            return ACTION_NAMES[base]
        if base == 0x00050000:
            return f"ERRNO({self.action & 0xFFFF})"
        return f"{self.action:#010x}"


def build_seccomp_data(nr: int, arch: int,
                       args: Sequence[int] = (0, 0, 0, 0, 0, 0),
                       instruction_pointer: int = 0) -> bytes:
    if len(args) > 6:
        raise ValueError("seccomp_data.args has exactly 6 slots")
    padded = tuple(list(args) + [0] * (6 - len(args)))
    return struct.pack("<IIQQQQQQQ",
                       nr & 0xFFFFFFFF,
                       arch & 0xFFFFFFFF,
                       instruction_pointer & 0xFFFFFFFFFFFFFFFF,
                       *[a & 0xFFFFFFFFFFFFFFFF for a in padded])


def simulate(program: bytes, nr: int, arch: int,
             args: Sequence[int] = (0, 0, 0, 0, 0, 0)) -> SimResult:
    """Исполнить программу против одного seccomp_data."""
    data = build_seccomp_data(nr, arch, args)
    if len(program) == 0 or len(program) % INSN.size != 0:
        raise SimulationError("malformed BPF program")
    n_insns = len(program) // INSN.size
    acc = 0
    pc = 0
    steps = 0
    while True:
        steps += 1
        if steps > MAX_STEPS:
            raise SimulationError(f"execution limit exceeded ({MAX_STEPS} steps)")
        if pc < 0 or pc >= n_insns:
            raise SimulationError(f"pc out of range: {pc} (program={n_insns})")
        code, jt, jf, k = INSN.unpack_from(program, pc * INSN.size)
        cls = code & 0x07
        if cls == _CLS_LD:
            if (code & 0xE0) != _LD_ABS_W:
                raise SimulationError(f"unsupported LD mode at {pc}: {code:#x}")
            if k + 4 > len(data):
                raise SimulationError(f"ld offset out of seccomp_data at {pc}: {k}")
            acc = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif cls == _CLS_ALU:
            if (code & 0xF8) != _ALU_AND_K:
                raise SimulationError(f"unsupported ALU op at {pc}: {code:#x}")
            acc &= k
            pc += 1
        elif cls == _CLS_JMP:
            op = code & 0xF0
            if op == _JMP_JA:
                pc += k + 1
            elif op == _JMP_JEQ:
                pc += (jt if acc == k else jf) + 1
            elif op == _JMP_JGT:
                pc += (jt if acc > k else jf) + 1
            elif op == _JMP_JSET:
                pc += (jt if (acc & k) else jf) + 1
            else:
                raise SimulationError(f"unsupported JMP op at {pc}: {code:#x}")
        elif cls == _CLS_RET:
            return SimResult(action=k, steps=steps)
        else:
            raise SimulationError(f"unsupported insn class at {pc}: {code:#x}")


# ----------------------------------------------------------------------------
# Политика-чеки (используются build-sec-profile.sh и тестами)
# ----------------------------------------------------------------------------

def check_cases(program: bytes, arch_name: str, arch_id: int,
                syscall_table: dict[str, int],
                cases: Iterable[tuple[str, str, Sequence[int], str]]
                ) -> list[str]:
    """Прогнать набор кейсов; вернуть список провалов (пусто = политика верна).

    :param cases: итерабельное (label, syscall_name, args, expected_action_name).
    """
    failures: list[str] = []
    for label, name, args, want in cases:
        nr = syscall_table.get(name)
        if nr is None:
            continue  # syscall отсутствует в ABI этой архитектуры
        try:
            res = simulate(program, nr, arch_id, args)
        except SimulationError as exc:
            failures.append(f"{label}: simulation error: {exc}")
            continue
        if res.action_name != want:
            failures.append(
                f"{label}: {name}{tuple(args)} -> {res.action_name}, "
                f"expected {want}")
    return failures


def strict_policy_cases(arch_name: str) -> list[tuple[str, str, tuple, str]]:
    """Эталонный набор проверок строгого профиля Приложения В."""
    cases: list[tuple[str, str, tuple, str]] = [
        # --- whitelist (группы 1-7 Приложения В) -> ALLOW
        ("wl/read", "read", (), "ALLOW"),
        ("wl/write", "write", (), "ALLOW"),
        ("wl/openat", "openat", (), "ALLOW"),
        ("wl/close", "close", (), "ALLOW"),
        ("wl/fstat", "fstat", (), "ALLOW"),
        # newfstatat/statx: реализация fstat()/stat() в glibc >= 2.33
        # (F-E-08 требует glibc; группа 1 Приложения В на современном ABI)
        ("wl/newfstatat", "newfstatat", (), "ALLOW"),
        ("wl/statx", "statx", (), "ALLOW"),
        ("wl/brk", "brk", (), "ALLOW"),
        ("wl/munmap", "munmap", (), "ALLOW"),
        ("wl/pread64", "pread64", (), "ALLOW"),
        ("wl/pwrite64", "pwrite64", (), "ALLOW"),
        ("wl/lseek", "lseek", (), "ALLOW"),
        ("wl/dup", "dup", (), "ALLOW"),
        ("wl/dup3", "dup3", (), "ALLOW"),
        ("wl/pipe2", "pipe2", (), "ALLOW"),
        ("wl/getdents64", "getdents64", (), "ALLOW"),
        ("wl/set_robust_list", "set_robust_list", (), "ALLOW"),
        ("wl/set_tid_address", "set_tid_address", (), "ALLOW"),
        ("wl/gettid", "gettid", (), "ALLOW"),
        ("wl/getpid", "getpid", (), "ALLOW"),
        ("wl/futex", "futex", (), "ALLOW"),
        ("wl/nanosleep", "nanosleep", (), "ALLOW"),
        ("wl/clock_gettime", "clock_gettime", (), "ALLOW"),
        ("wl/clock_nanosleep", "clock_nanosleep", (), "ALLOW"),
        ("wl/gettimeofday", "gettimeofday", (), "ALLOW"),
        ("wl/getrandom", "getrandom", (), "ALLOW"),
        ("wl/connect", "connect", (), "ALLOW"),
        ("wl/bind", "bind", (), "ALLOW"),
        ("wl/accept4", "accept4", (), "ALLOW"),
        ("wl/sendmsg", "sendmsg", (), "ALLOW"),
        ("wl/recvmsg", "recvmsg", (), "ALLOW"),
        ("wl/shutdown", "shutdown", (), "ALLOW"),
        ("wl/getsockname", "getsockname", (), "ALLOW"),
        ("wl/rt_sigaction", "rt_sigaction", (), "ALLOW"),
        ("wl/rt_sigprocmask", "rt_sigprocmask", (), "ALLOW"),
        ("wl/rt_sigreturn", "rt_sigreturn", (), "ALLOW"),
        ("wl/sigaltstack", "sigaltstack", (), "ALLOW"),
        ("wl/exit", "exit", (), "ALLOW"),
        ("wl/exit_group", "exit_group", (), "ALLOW"),
        ("wl/uname", "uname", (), "ALLOW"),
        ("wl/sysinfo", "sysinfo", (), "ALLOW"),
        ("wl/getuid", "getuid", (), "ALLOW"),
        ("wl/getgid", "getgid", (), "ALLOW"),
        ("wl/geteuid", "geteuid", (), "ALLOW"),
        ("wl/getegid", "getegid", (), "ALLOW"),
        # --- явные запреты -> KILL_PROCESS
        ("ban/clone3", "clone3", (), "KILL_PROCESS"),
        ("ban/execve", "execve", (), "KILL_PROCESS"),
        ("ban/execveat", "execveat", (), "KILL_PROCESS"),
        ("ban/ptrace", "ptrace", (), "KILL_PROCESS"),
        ("ban/mount", "mount", (), "KILL_PROCESS"),
        ("ban/umount2", "umount2", (), "KILL_PROCESS"),
        ("ban/chroot", "chroot", (), "KILL_PROCESS"),
        ("ban/pivot_root", "pivot_root", (), "KILL_PROCESS"),
        ("ban/bpf", "bpf", (), "KILL_PROCESS"),
        ("ban/keyctl", "keyctl", (), "KILL_PROCESS"),
        ("ban/init_module", "init_module", (), "KILL_PROCESS"),
        ("ban/finit_module", "finit_module", (), "KILL_PROCESS"),
        ("ban/delete_module", "delete_module", (), "KILL_PROCESS"),
        ("ban/perf_event_open", "perf_event_open", (), "KILL_PROCESS"),
        ("ban/setns", "setns", (), "KILL_PROCESS"),
        ("ban/unshare", "unshare", (), "KILL_PROCESS"),
        ("ban/userfaultfd", "userfaultfd", (), "KILL_PROCESS"),
        # --- default action для syscall вне whitelist
        ("def/ioctl", "ioctl", (), "KILL_PROCESS"),
        ("def/fcntl", "fcntl", (), "KILL_PROCESS"),
        ("def/kill", "kill", (), "KILL_PROCESS"),
        ("def/fork", "fork", (), "KILL_PROCESS"),
        ("def/vfork", "vfork", (), "KILL_PROCESS"),
        ("def/wait4", "wait4", (), "KILL_PROCESS"),
        # --- socket: только AF_UNIX
        ("sock/AF_UNIX", "socket", (1,), "ALLOW"),
        ("sock/AF_INET", "socket", (2,), "KILL_PROCESS"),
        ("sock/AF_INET6", "socket", (10,), "KILL_PROCESS"),
        ("sock/AF_NETLINK", "socket", (16,), "KILL_PROCESS"),
        ("sock/AF_PACKET", "socket", (17,), "KILL_PROCESS"),
        ("sock/AF_ALG", "socket", (38,), "KILL_PROCESS"),
        ("sock/AF_UNKNOWN(99)", "socket", (99,), "KILL_PROCESS"),
        # --- clone: exact flag match
        ("clone/spec-mask", "clone", (0x10F00,), "ALLOW"),
        ("clone/glibc-mask", "clone", (0x3D0F00,), "ALLOW"),
        ("clone/fork-flags0", "clone", (0,), "KILL_PROCESS"),
        ("clone/newuser", "clone", (0x10F00 | 0x10000000,), "KILL_PROCESS"),
        ("clone/extra-bit", "clone", (0x3D0F00 | 0x2,), "KILL_PROCESS"),
        # --- mmap/mprotect: PROT_EXEC guard
        ("mmap/RW", "mmap", (0, 4096, 3, 0x22, -1 & 0xFFFFFFFFFFFFFFFF, 0), "ALLOW"),
        ("mmap/RX", "mmap", (0, 4096, 5, 0x22, -1 & 0xFFFFFFFFFFFFFFFF, 0), "KILL_PROCESS"),
        ("mmap/RWX", "mmap", (0, 4096, 7, 0x22, -1 & 0xFFFFFFFFFFFFFFFF, 0), "KILL_PROCESS"),
        ("mmap/hi-word-prot", "mmap", (0, 4096, (1 << 32) | 3), "ALLOW"),
        ("mprotect/RW", "mprotect", (0, 4096, 3), "ALLOW"),
        ("mprotect/EXEC", "mprotect", (0, 4096, 4), "KILL_PROCESS"),
        ("mprotect/RWX", "mprotect", (0, 4096, 7), "KILL_PROCESS"),
    ]
    if arch_name == "x86_64":
        cases += [
            ("wl/dup2", "dup2", (), "ALLOW"),
            ("x32/mmap2", "mmap2", (), "KILL_PROCESS"),
        ]
    return cases
