"""Unit-тесты ассемблера classic BPF (ztseccomp.bpf)."""
from __future__ import annotations

import struct

import pytest

from ztseccomp.bpf import (
    BPF_ALU,
    BPF_AND,
    BPF_JMP,
    BPF_JEQ,
    BPF_K,
    BPF_LD,
    BPF_ABS,
    BPF_W,
    OFF_ARCH,
    OFF_NR,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_KILL_PROCESS,
    Assembler,
    arg_hi_offset,
    arg_lo_offset,
    disassemble,
    insn_count,
)

INSN = struct.Struct("<HBBI")


def test_offsets_match_seccomp_data_layout():
    # struct seccomp_data: int nr; u32 arch; u64 ip; u64 args[6];
    assert OFF_NR == 0
    assert OFF_ARCH == 4
    assert arg_lo_offset(0) == 16
    assert arg_hi_offset(0) == 20
    assert arg_lo_offset(5) == 56
    assert arg_hi_offset(5) == 60


def test_arg_index_validation():
    with pytest.raises(ValueError):
        arg_lo_offset(6)
    with pytest.raises(ValueError):
        arg_lo_offset(-1)


def test_minimal_arch_guard_program():
    asm = Assembler()
    asm.ld_abs(OFF_ARCH)
    asm.jeq(0xC000003E, jt=1, jf=0)
    asm.ret(SECCOMP_RET_KILL_PROCESS)
    asm.ld_abs(OFF_NR)
    asm.ret(SECCOMP_RET_ALLOW)
    prog = asm.assemble()
    assert len(prog) == 5 * INSN.size
    assert insn_count(prog) == 5
    code0, jt0, jf0, k0 = INSN.unpack_from(prog, 0)
    assert code0 == BPF_LD | BPF_W | BPF_ABS
    assert k0 == OFF_ARCH
    code1, jt1, jf1, k1 = INSN.unpack_from(prog, INSN.size)
    assert code1 == BPF_JMP | BPF_JEQ | BPF_K
    assert (jt1, jf1, k1) == (1, 0, 0xC000003E)


def test_label_resolution_forward_and_back_error():
    asm = Assembler()
    asm.jeq(1, jt="target", jf=0)
    asm.ret(SECCOMP_RET_KILL_PROCESS)
    asm.label("target")
    asm.ret(SECCOMP_RET_ALLOW)
    prog = asm.assemble()
    _, jt, _, _ = INSN.unpack_from(prog, 0)
    assert jt == 1  # target на insn 2: 2 - (0 + 1) = 1


def test_undefined_label_raises():
    asm = Assembler()
    asm.jeq(1, jt="nowhere", jf=0)
    asm.ret(SECCOMP_RET_ALLOW)
    with pytest.raises(ValueError, match="undefined label"):
        asm.assemble()


def test_jump_overflow_u8_raises():
    asm = Assembler()
    asm.jeq(1, jt="far", jf=0)
    for _ in range(300):
        asm.ret(SECCOMP_RET_ALLOW)
    asm.label("far")
    asm.ret(SECCOMP_RET_ALLOW)
    with pytest.raises(ValueError, match="out of u8 range"):
        asm.assemble()


def test_ja_uses_32bit_k_for_long_jumps():
    asm = Assembler()
    asm.jmp("far")
    for _ in range(1000):
        asm.ret(SECCOMP_RET_ALLOW)
    asm.label("far")
    asm.ret(SECCOMP_RET_KILL_PROCESS)
    prog = asm.assemble()
    _, _, _, k = INSN.unpack_from(prog, 0)
    assert k == 1000  # JA: смещение в 32-битном k


def test_duplicate_label_raises():
    asm = Assembler()
    asm.label("x")
    with pytest.raises(ValueError, match="duplicate label"):
        asm.label("x")


def test_empty_program_raises():
    with pytest.raises(ValueError, match="empty"):
        Assembler().assemble()


def test_and_k_encoding():
    asm = Assembler()
    asm.and_k(0x4)
    asm.ret(SECCOMP_RET_ALLOW)
    prog = asm.assemble()
    code, _, _, k = INSN.unpack_from(prog, 0)
    assert code == BPF_ALU | BPF_AND | BPF_K
    assert k == 0x4


def test_disassemble_roundtrip():
    asm = Assembler()
    asm.ld_abs(OFF_NR)
    asm.jeq(435, jt="kill", jf=0)
    asm.ret(SECCOMP_RET_ALLOW)
    asm.label("kill")
    asm.ret(SECCOMP_RET_KILL_PROCESS)
    lines = disassemble(asm.assemble())
    assert lines[0] == "0000: ld [0]"
    assert "jeq #0x1b3" in lines[1]
    assert lines[2] == "0002: ret ALLOW"
    assert lines[3] == "0003: ret KILL_PROCESS"
