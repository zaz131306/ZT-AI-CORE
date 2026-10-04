"""Симуляторная верификация скомпилированной политики (без ядра)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ztseccomp._tables_gen import (
    AARCH64_SYSCALLS,
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    SYSCALL_TABLES,
    X86_64_SYSCALLS,
)
from ztseccomp.bpf import SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS
from ztseccomp.profile import compile_profile
from ztseccomp.simulate import (
    SimulationError,
    check_cases,
    simulate,
    strict_policy_cases,
)

AUDIT = {"x86_64": AUDIT_ARCH_X86_64, "aarch64": AUDIT_ARCH_AARCH64}


def _compile(strict_profile_path: Path, arch: str) -> bytes:
    prog, _ = compile_profile(strict_profile_path, arch=arch)
    return prog


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_strict_policy_full_suite(strict_profile_path: Path, arch: str):
    prog = _compile(strict_profile_path, arch)
    failures = check_cases(prog, arch, AUDIT[arch], SYSCALL_TABLES[arch],
                           strict_policy_cases(arch))
    assert failures == [], "\n".join(failures)


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_wrong_audit_arch_kills(strict_profile_path: Path, arch: str):
    prog = _compile(strict_profile_path, arch)
    res = simulate(prog, 1, AUDIT[arch] ^ 0xDEADBEEF)
    assert res.action == SECCOMP_RET_KILL_PROCESS


def test_x32_abi_nr_bit_kills(strict_profile_path: Path):
    # x32: nr | 0x40000000 при «чужом» arch — guard обязан убить.
    prog = _compile(strict_profile_path, "x86_64")
    res = simulate(prog, 1 | 0x40000000, AUDIT_ARCH_X86_64)
    assert res.action == SECCOMP_RET_KILL_PROCESS


def test_clone_flag_combinations(strict_profile_path: Path):
    prog = _compile(strict_profile_path, "x86_64")
    clone = X86_64_SYSCALLS["clone"]
    allowed_masks = [0x10F00, 0x3D0F00]
    denied_masks = [0x0, 0x1, 0x100, 0x10F01, 0x3D0F01, 0x1000010F00,
                    0x10F00 | 0x10000000,  # + CLONE_NEWUSER
                    0x3D0F00 | 0x08000000,  # + CLONE_NEWPID? (0x20000000) — любой чужой бит
                    1 << 40]               # бит в старшем слове
    for mask in allowed_masks:
        res = simulate(prog, clone, AUDIT_ARCH_X86_64, (mask,))
        assert res.action == SECCOMP_RET_ALLOW, f"mask {mask:#x} должна разрешаться"
    for mask in denied_masks:
        res = simulate(prog, clone, AUDIT_ARCH_X86_64, (mask,))
        assert res.action == SECCOMP_RET_KILL_PROCESS, f"mask {mask:#x} должна убивать"


def test_socket_family_matrix(strict_profile_path: Path):
    prog = _compile(strict_profile_path, "x86_64")
    sock = X86_64_SYSCALLS["socket"]
    expect = {
        1: SECCOMP_RET_ALLOW,        # AF_UNIX
        2: SECCOMP_RET_KILL_PROCESS,  # AF_INET
        10: SECCOMP_RET_KILL_PROCESS, # AF_INET6
        16: SECCOMP_RET_KILL_PROCESS, # AF_NETLINK
        17: SECCOMP_RET_KILL_PROCESS, # AF_PACKET
        0: SECCOMP_RET_KILL_PROCESS,
        42: SECCOMP_RET_KILL_PROCESS,
        (1 << 33) | 1: SECCOMP_RET_KILL_PROCESS,  # AF_UNIX + мусор в старшем слове
    }
    for family, want in expect.items():
        res = simulate(prog, sock, AUDIT_ARCH_X86_64, (family,))
        assert res.action == want, f"family={family}: {res.action_name}"


def test_prot_exec_guard_both_words(strict_profile_path: Path):
    prog = _compile(strict_profile_path, "x86_64")
    mmap = X86_64_SYSCALLS["mmap"]
    # PROT_EXEC в младшем слове
    assert simulate(prog, mmap, AUDIT_ARCH_X86_64,
                    (0, 4096, 0x4)).action == SECCOMP_RET_KILL_PROCESS
    # PROT_EXEC|PROT_READ|PROT_WRITE
    assert simulate(prog, mmap, AUDIT_ARCH_X86_64,
                    (0, 4096, 0x7)).action == SECCOMP_RET_KILL_PROCESS
    # бит в старшем слове prot не влияет (mask=0x4)
    assert simulate(prog, mmap, AUDIT_ARCH_X86_64,
                    (0, 4096, (1 << 32) | 0x3)).action == SECCOMP_RET_ALLOW


def test_ioctl_only_tcgets_fionbio(strict_profile_path: Path):
    prog = _compile(strict_profile_path, "x86_64")
    ioctl = X86_64_SYSCALLS["ioctl"]
    allowed = [0x5401, 0x5421]           # TCGETS, FIONBIO
    denied = [0x0, 0x5409, 0x540A, 0x541B, 0x8933, 0x5422, (1 << 32) | 0x5401]
    for req in allowed:
        assert simulate(prog, ioctl, AUDIT_ARCH_X86_64,
                        (3, req)).action == SECCOMP_RET_ALLOW, hex(req)
    for req in denied:
        assert simulate(prog, ioctl, AUDIT_ARCH_X86_64,
                        (3, req)).action == SECCOMP_RET_KILL_PROCESS, hex(req)


def test_every_syscall_terminates(strict_profile_path: Path):
    """Все nr 0..600 дают валидный вердикт (нет циклов/выходов за границы)."""
    prog = _compile(strict_profile_path, "x86_64")
    allowed_nrs = {res for res in
                   (simulate(prog, nr, AUDIT_ARCH_X86_64).action
                    for nr in range(0, 601))}
    assert allowed_nrs <= {SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS}


def test_extended_profile_dev_semantics(extended_profile_path: Path):
    prog, report = compile_profile(extended_profile_path, arch="x86_64")
    assert report.default_action == "SCMP_ACT_ERRNO(1)"
    T = X86_64_SYSCALLS
    # жёсткие запреты сохраняются
    for name in ("clone3", "execve", "ptrace", "bpf"):
        if name in T:
            assert simulate(prog, T[name], AUDIT_ARCH_X86_64).action == \
                SECCOMP_RET_KILL_PROCESS, name
    # dev-набор разрешён
    for name in ("ioctl", "epoll_pwait", "newfstatat", "fcntl", "tgkill"):
        if name in T:
            res = simulate(prog, T[name], AUDIT_ARCH_X86_64, (3, 0x5401) if name == "ioctl" else ())
            assert res.action == SECCOMP_RET_ALLOW, name
    # вне whitelist → ERRNO(EPERM), процесс выживает
    res = simulate(prog, T.get("personality", 135), AUDIT_ARCH_X86_64)
    assert res.action == (0x00050000 | 1)


def test_simulation_rejects_garbage_program():
    with pytest.raises(SimulationError):
        simulate(b"\x00", 1, AUDIT_ARCH_X86_64)
