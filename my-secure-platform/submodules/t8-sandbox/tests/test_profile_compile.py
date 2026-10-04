"""Тесты компилятора профиля: валидация JSON, детерминизм, коллизии, отчёты."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ztseccomp.profile import (
    ArgMatcher,
    ProfileError,
    compile_profile,
    load_profile,
    native_arch,
    parse_rules,
    validate_profile_schema,
)
from ztseccomp.bpf import SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS


def test_native_arch_supported():
    assert native_arch() in ("x86_64", "aarch64")


def test_strict_profile_loads_and_validates(strict_profile_path: Path):
    data = load_profile(strict_profile_path)
    assert data["defaultAction"] == "SCMP_ACT_KILL_PROCESS"
    validate_profile_schema(data)
    rules, default = parse_rules(data)
    assert default == SECCOMP_RET_KILL_PROCESS
    assert len(rules) >= 15


def test_strict_profile_compiles_both_arches(strict_profile_path: Path):
    for arch in ("x86_64", "aarch64"):
        prog, report = compile_profile(strict_profile_path, arch=arch)
        assert len(prog) % 8 == 0
        assert 0 < report.instruction_count <= 4096
        assert report.rules_compiled > 0
        assert report.default_action == "SCMP_ACT_KILL_PROCESS"


def test_extended_profile_default_is_errno(extended_profile_path: Path):
    prog, report = compile_profile(extended_profile_path, arch="x86_64")
    assert report.default_action == "SCMP_ACT_ERRNO(1)"
    assert len(prog) > 0


def test_compilation_is_deterministic(strict_profile_path: Path):
    p1, _ = compile_profile(strict_profile_path, arch="x86_64")
    p2, _ = compile_profile(strict_profile_path, arch="x86_64")
    assert p1 == p2


def test_unsupported_arch_rejected(strict_profile_path: Path):
    with pytest.raises(ProfileError, match="unsupported arch"):
        compile_profile(strict_profile_path, arch="riscv64")


def test_invalid_default_action_rejected():
    with pytest.raises(ProfileError, match="defaultAction"):
        validate_profile_schema({"defaultAction": "SCMP_ACT_HUG",
                                 "syscalls": [{"names": ["read"],
                                               "action": "SCMP_ACT_ALLOW"}]})


def test_empty_syscalls_rejected():
    with pytest.raises(ProfileError, match="non-empty"):
        validate_profile_schema({"defaultAction": "SCMP_ACT_ALLOW",
                                 "syscalls": []})


def test_bad_arg_op_rejected():
    with pytest.raises(ProfileError, match="unsupported arg op"):
        ArgMatcher.parse({"index": 0, "value": 1, "op": "SCMP_CMP_GT"})


def test_arg_index_range():
    with pytest.raises(ProfileError, match="out of range"):
        ArgMatcher.parse({"index": 6, "value": 1})


def test_errno_action_parsing():
    data = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "errnoRet": 38,
        "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}],
    }
    _, default = parse_rules(data)
    assert default == SECCOMP_RET_ERRNO | 38


def test_masked_eq_value_outside_mask_rejected_at_compile():
    # value имеет биты вне mask → правило заведомо ложно; компилятор
    # эмитирует переход на fail, но обязан собрать программу.
    data = {
        "defaultAction": "SCMP_ACT_KILL_PROCESS",
        "syscalls": [{
            "names": ["mmap"], "action": "SCMP_ACT_KILL_PROCESS",
            "args": [{"index": 2, "value": 0x8, "mask": 0x4,
                      "op": "SCMP_CMP_MASKED_EQ"}],
        }],
    }
    prog, _ = compile_profile(data, arch="x86_64")
    assert len(prog) > 0


def test_collision_detector_catches_compat_alias():
    # На aarch64 __NR_mmap2 == __NR_mmap (compat-алиас): kill-правило mmap2
    # конфликтовало бы с allow-правилом mmap — компилятор обязан отказаться.
    data = {
        "defaultAction": "SCMP_ACT_KILL_PROCESS",
        "syscalls": [
            {"names": ["mmap2"], "action": "SCMP_ACT_KILL_PROCESS"},
            {"names": ["mmap"], "action": "SCMP_ACT_ALLOW"},
        ],
    }
    with pytest.raises(ProfileError, match="collision"):
        compile_profile(data, arch="aarch64")
    # На x86_64 mmap2 отсутствует в ABI — коллизии нет.
    prog, report = compile_profile(data, arch="x86_64")
    assert "mmap2" in report.skipped_names


def test_report_skipped_names(strict_profile_path: Path):
    _, report = compile_profile(strict_profile_path, arch="aarch64")
    # dup2 отсутствует в asm-generic ABI
    assert "dup2" in report.skipped_names


def test_profile_json_meta_matches_spec(strict_profile_path: Path):
    data = json.loads(strict_profile_path.read_text(encoding="utf-8"))
    meta = data["meta"]
    assert meta["version"] == "2.4"
    assert "Приложение В" in meta["spec_reference"]
    assert set(meta["archs"]) == {"x86_64", "aarch64"}


def test_whitelist_covers_appendix_b_groups(strict_profile_path: Path):
    """Все syscall из whitelist Приложения В присутствуют в профиле."""
    data = json.loads(strict_profile_path.read_text(encoding="utf-8"))
    allowed_names = set()
    for entry in data["syscalls"]:
        if entry["action"] == "SCMP_ACT_ALLOW":
            allowed_names.update(entry["names"])
    appendix_b = {
        "read", "write", "openat", "close", "fstat", "mmap", "mprotect",
        "munmap", "brk", "pread64", "pwrite64", "lseek", "dup", "dup2",
        "dup3", "pipe2", "getdents64", "clone", "set_robust_list",
        "set_tid_address", "gettid", "getpid", "futex", "nanosleep",
        "clock_gettime", "clock_nanosleep", "gettimeofday", "getrandom",
        "socket", "connect", "bind", "accept4", "sendmsg", "recvmsg",
        "shutdown", "getsockname", "rt_sigaction", "rt_sigprocmask",
        "rt_sigreturn", "sigaltstack", "exit", "exit_group", "uname",
        "sysinfo", "getuid", "getgid", "geteuid", "getegid",
    }
    missing = appendix_b - allowed_names
    assert not missing, f"Приложение В: отсутствуют в ALLOW-правилах: {missing}"


def test_banned_appendix_b_kill_rules(strict_profile_path: Path):
    data = json.loads(strict_profile_path.read_text(encoding="utf-8"))
    killed = set()
    for entry in data["syscalls"]:
        if entry["action"] == "SCMP_ACT_KILL_PROCESS" and not entry.get("args"):
            killed.update(entry["names"])
    for banned in ("execve", "execveat", "clone3", "ptrace", "mount",
                   "umount2", "chroot", "pivot_root", "bpf"):
        assert banned in killed, f"{banned} обязан иметь явный KILL"
