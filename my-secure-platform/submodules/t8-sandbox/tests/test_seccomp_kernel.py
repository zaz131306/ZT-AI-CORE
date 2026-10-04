"""Ядерные тесты SECCOMP-фильтра в fork'нутых процессах (AC-01, AC-09).

Каждый тест применяет скомпилированный строгий профиль в ребёнке и проверяет
реакцию ядра: ALLOW-операции завершаются штатно (exit 42), запрещённые —
SIGSYS (SECCOMP_RET_KILL_PROCESS).
"""
from __future__ import annotations

import ctypes
import mmap as mmap_mod
import os
import signal
import socket
import sys
import time
from pathlib import Path

import pytest

from conftest import requires_fork, requires_seccomp
from ztseccomp.apply import apply_bpf_filter
from ztseccomp.profile import compile_profile

EXIT_OK = 42


def _compile_strict(strict_profile_path: Path) -> bytes:
    prog, _ = compile_profile(strict_profile_path)
    return prog


def _run_child(program: bytes, action) -> tuple[bool, int, int]:
    """Запустить action в ребёнке с применённым фильтром.

    :returns: (signaled, termsig, exitcode)
    """
    pid = os.fork()
    if pid == 0:
        try:
            apply_bpf_filter(program)
            action()
        except BaseException:
            os._exit(98)
        os._exit(EXIT_OK)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return True, os.WTERMSIG(status), -1
    return False, 0, os.WEXITSTATUS(status)


@pytest.fixture()
def strict_program(strict_profile_path: Path) -> bytes:
    return _compile_strict(strict_profile_path)


@requires_fork
@requires_seccomp
def test_allowed_unix_socket_survives(strict_program: bytes):
    def action():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.close()
    sig, term, code = _run_child(strict_program, action)
    assert not sig and code == EXIT_OK


@requires_fork
@requires_seccomp
def test_ac01_af_INET_killed(strict_program: bytes):
    def action():
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sig, term, _ = _run_child(strict_program, action)
    assert sig and term == signal.SIGSYS, "AC-01: socket(AF_INET) обязан убиваться"


@requires_fork
@requires_seccomp
def test_ac01_af_inet6_killed(strict_program: bytes):
    def action():
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sig, term, _ = _run_child(strict_program, action)
    assert sig and term == signal.SIGSYS


@requires_fork
@requires_seccomp
def test_clone3_totally_banned(strict_program: bytes):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    from ztseccomp._tables_gen import X86_64_SYSCALLS, AARCH64_SYSCALLS
    import platform
    table = AARCH64_SYSCALLS if platform.machine() == "aarch64" else X86_64_SYSCALLS
    nr_clone3 = table["clone3"]

    def action():
        libc.syscall(nr_clone3, 0, 0, 0, 0)
    sig, term, _ = _run_child(strict_program, action)
    assert sig and term == signal.SIGSYS, "clone3 обязан убиваться (Приложение В)"


@requires_fork
@requires_seccomp
def test_ac09_mmap_prot_exec_killed(strict_program: bytes):
    def action():
        mmap_mod.mmap(-1, 4096, prot=mmap_mod.PROT_READ | mmap_mod.PROT_EXEC)
    sig, term, _ = _run_child(strict_program, action)
    assert sig and term == signal.SIGSYS, \
        "AC-09: mmap(PROT_EXEC) после arming обязан убиваться"


@requires_fork
@requires_seccomp
def test_mprotect_prot_exec_killed(strict_program: bytes):
    def action():
        m = mmap_mod.mmap(-1, 4096, prot=mmap_mod.PROT_READ | mmap_mod.PROT_WRITE)
        ctypes_libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = ctypes.c_void_p.from_buffer(m) if False else None  # noqa: F841
        # mprotect через libc на адрес анонимного отображения
        import ctypes as _ct
        buf_addr = _ct.addressof(_ct.c_char.from_buffer(m))
        ctypes_libc.mprotect(_ct.c_void_p(buf_addr & ~0xFFF), 4096,
                             mmap_mod.PROT_READ | mmap_mod.PROT_EXEC)
    sig, term, _ = _run_child(strict_program, action)
    assert sig and term == signal.SIGSYS


@requires_fork
@requires_seccomp
def test_mmap_rw_allowed(strict_program: bytes):
    def action():
        m = mmap_mod.mmap(-1, 4096,
                          prot=mmap_mod.PROT_READ | mmap_mod.PROT_WRITE)
        m[0:4] = b"ztai"
        m.close()
    sig, term, code = _run_child(strict_program, action)
    assert not sig and code == EXIT_OK


@requires_fork
@requires_seccomp
def test_file_io_allowed(strict_program: bytes, tmp_path: Path):
    target = tmp_path / "f.txt"
    target.write_text("data")

    def action():
        with open(str(target), "r") as fh:
            assert fh.read() == "data"
        with open(str(target), "a") as fh:
            fh.write("+")
            fh.flush()
    sig, term, code = _run_child(strict_program, action)
    assert not sig and code == EXIT_OK, \
        f"файловый ввод-вывод под строгим профилем (signaled={sig} term={term} code={code})"


@requires_fork
@requires_seccomp
def test_execve_banned(strict_program: bytes):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    def action():
        # execve("/bin/true", ...) — запрещён после bootstrap
        libc.execve(b"/bin/true", None, None)
    sig, term, _ = _run_child(strict_program, action)
    assert sig and term == signal.SIGSYS


@requires_fork
@requires_seccomp
def test_heartbeat_loop_survives(strict_program: bytes):
    """Минимальный рабочий цикл D8: sleep + write + exit под строгим профилем."""
    def action():
        for _ in range(3):
            time.sleep(0.02)
        sys.stderr.write("heartbeat\n")
        sys.stderr.flush()
    sig, term, code = _run_child(strict_program, action)
    assert not sig and code == EXIT_OK


@requires_fork
@requires_seccomp
def test_filter_is_inherited_by_clone_thread(strict_program: bytes):
    """Поток (clone с glibc-маской) наследует фильтр; AF_INET в потоке — SIGSYS."""
    import threading

    result = {}

    def thread_body():
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result["survived"] = True
        except BaseException:
            result["survived"] = False

    def action():
        t = threading.Thread(target=thread_body, daemon=True)
        t.start()
        t.join(2)
        # если поток убит SIGSYS — процесс целиком умирает (KILL_PROCESS),
        # поэтому до сюда дело не дойдёт; страховка:
        os._exit(EXIT_OK if result.get("survived") else 97)
    sig, term, code = _run_child(strict_program, action)
    # Ожидаем: KILL_PROCESS убивает ВЕСЬ процесс при нарушении в потоке.
    assert sig and term == signal.SIGSYS, \
        f"нарушение в потоке должно убить процесс (sig={sig} term={term} code={code})"
