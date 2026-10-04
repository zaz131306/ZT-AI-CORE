"""ztseccomp — компилятор SECCOMP-профиля ZT-AI-CORE (custom classic BPF).

Реализует F-E-02 / Приложение В ТЗ v2.4:
  * строгий whitelist syscall с default-действием SCMP_ACT_KILL_PROCESS;
  * exact flag match (SCMP_CMP_EQ) для ``clone``;
  * полный запрет ``clone3`` (SCMP_ACT_KILL_PROCESS);
  * кастомный BPF-контроль ``PROT_EXEC``: ``args[2] & PROT_EXEC -> KILL``
    для mmap/mprotect (защита Eager Loading, F-E-07);
  * socket/connect/bind — только AF_UNIX (args[0] == 1).

Модули:
  * :mod:`ztseccomp.bpf`      — ассемблер classic BPF (sock_filter);
  * :mod:`ztseccomp.profile`  — JSON-профиль (Приложение В) -> BPF-программа;
  * :mod:`ztseccomp.apply`    — применение фильтра через prctl(2)/seccomp(2),
                                capability drop (PR_CAPBSET_DROP, PR_SET_NO_NEW_PRIVS);
  * :mod:`ztseccomp.compile`  — CLI: ``python3 -m ztseccomp.compile``.

Таблицы номеров syscall генерируются из заголовков ядра:
``tools/gen_syscall_tables.py`` (ручное редактирование запрещено).
"""
from __future__ import annotations

from .bpf import (
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_LOG,
    SECCOMP_RET_TRAP,
    Assembler,
)
from .profile import (
    CompileReport,
    ProfileRule,
    compile_profile,
    load_profile,
    native_arch,
)

__all__ = [
    "Assembler",
    "CompileReport",
    "ProfileRule",
    "compile_profile",
    "load_profile",
    "native_arch",
    "SECCOMP_RET_ALLOW",
    "SECCOMP_RET_ERRNO",
    "SECCOMP_RET_KILL_PROCESS",
    "SECCOMP_RET_KILL_THREAD",
    "SECCOMP_RET_TRAP",
    "SECCOMP_RET_LOG",
]

__version__ = "2.4.0"
