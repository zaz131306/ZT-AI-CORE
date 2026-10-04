"""Ассемблер classic BPF (cBPF) для SECCOMP-фильтров.

Формат инструкции (include/uapi/linux/filter.h)::

    struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; };

Раскладка ``struct seccomp_data`` (include/uapi/linux/seccomp.h)::

    int   nr;                 // offset 0   — номер syscall
    __u32 arch;               // offset 4   — AUDIT_ARCH_*
    __u64 instruction_pointer;// offset 8
    __u64 args[6];            // offset 16 + 8*i

cBPF работает с 32-битными словами: на little-endian 64-битный аргумент
``args[i]`` читается двумя загрузками — младшее слово по смещению
``16+8*i``, старшее — ``16+8*i+4``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Union

# --- Классы/моды/опкоды BPF (include/uapi/linux/filter.h) --------------------
BPF_LD = 0x00
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06

BPF_W = 0x00
BPF_ABS = 0x20
BPF_K = 0x00

BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JSET = 0x40
BPF_JA = 0x00

BPF_AND = 0x50

# --- Действия seccomp (include/uapi/linux/seccomp.h) -------------------------
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000  # младшие 16 бит — errno
SECCOMP_RET_LOG = 0x7FFC0000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_KILL_PROCESS = 0x80000000

SECCOMP_RET_ACTION_FULL = 0xFFFF0000

# --- Смещения в seccomp_data --------------------------------------------------
OFF_NR = 0
OFF_ARCH = 4
OFF_INSTRUCTION_POINTER = 8
OFF_ARGS = 16

BPF_MAXINSNS = 4096

_SOCK_FILTER = struct.Struct("<HBBI")

JumpTarget = Union[int, str]


def arg_lo_offset(index: int) -> int:
    """Смещение младшего 32-битного слова args[index] (little-endian)."""
    if not 0 <= index <= 5:
        raise ValueError(f"arg index out of range: {index}")
    return OFF_ARGS + 8 * index


def arg_hi_offset(index: int) -> int:
    """Смещение старшего 32-битного слова args[index] (little-endian)."""
    return arg_lo_offset(index) + 4


@dataclass
class Insn:
    """Одна инструкция sock_filter; jt/jf/k могут быть метками (str) до сборки."""

    code: int
    jt: JumpTarget = 0
    jf: JumpTarget = 0
    k: Union[int, str] = 0


@dataclass
class Assembler:
    """Двухпроходный ассемблер: метки разрешаются в :meth:`assemble`.

    Относительные переходы jt/jf отсчитываются от СЛЕДУЮЩЕЙ инструкции
    (требование ядра); для ``BPF_JA`` смещение хранится в ``k``.
    """

    insns: list[Insn] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)

    # -- эмиссия -------------------------------------------------------------
    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f"duplicate label: {name!r}")
        self.labels[name] = len(self.insns)

    def emit(self, code: int, jt: JumpTarget = 0, jf: JumpTarget = 0,
             k: Union[int, str] = 0) -> int:
        self.insns.append(Insn(code, jt, jf, k))
        return len(self.insns) - 1

    def ld_abs(self, offset: int) -> None:
        """BPF_LD|BPF_W|BPF_ABS — загрузка 32-битного слова seccomp_data."""
        self.emit(BPF_LD | BPF_W | BPF_ABS, k=offset)

    def and_k(self, value: int) -> None:
        """BPF_ALU|BPF_AND|BPF_K — acc &= value (для MASKED_EQ)."""
        self.emit(BPF_ALU | BPF_AND | BPF_K, k=value & 0xFFFFFFFF)

    def jeq(self, value: int, jt: JumpTarget, jf: JumpTarget) -> None:
        self.emit(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, value & 0xFFFFFFFF)

    def jgt(self, value: int, jt: JumpTarget, jf: JumpTarget) -> None:
        self.emit(BPF_JMP | BPF_JGT | BPF_K, jt, jf, value & 0xFFFFFFFF)

    def jset(self, mask: int, jt: JumpTarget, jf: JumpTarget) -> None:
        self.emit(BPF_JMP | BPF_JSET | BPF_K, jt, jf, mask & 0xFFFFFFFF)

    def jmp(self, target: JumpTarget) -> None:
        """BPF_JMP|BPF_JA — безусловный переход (смещение в k)."""
        self.emit(BPF_JMP | BPF_JA, k=target)

    def ret(self, value: int) -> None:
        self.emit(BPF_RET | BPF_K, k=value & 0xFFFFFFFF)

    # -- разрешение меток ------------------------------------------------------
    def _resolve(self, pos: int, target: JumpTarget, field_name: str) -> int:
        if isinstance(target, int):
            resolved = target
        else:
            if target not in self.labels:
                raise ValueError(f"undefined label {target!r} at insn #{pos}")
            resolved = self.labels[target] - (pos + 1)
        if resolved < 0 or resolved > 255:
            raise ValueError(
                f"{field_name} jump out of u8 range at insn #{pos}: {resolved}"
            )
        return resolved

    def assemble(self) -> bytes:
        """Собрать программу в байты sock_filter[]; проверить лимит инструкций."""
        if len(self.insns) > BPF_MAXINSNS:
            raise ValueError(
                f"filter too large: {len(self.insns)} > {BPF_MAXINSNS} instructions"
            )
        if not self.insns:
            raise ValueError("empty BPF program")
        out = bytearray()
        for pos, ins in enumerate(self.insns):
            jt = self._resolve(pos, ins.jt, "jt") if isinstance(ins.jt, (int, str)) and _is_jmp(ins.code) else 0
            jf = self._resolve(pos, ins.jf, "jf") if _is_jmp(ins.code) else 0
            k = ins.k
            if isinstance(k, str):
                if not _is_jmp(ins.code):
                    raise ValueError(f"label in k of non-jmp insn #{pos}")
                # BPF_JA хранит смещение в k (от следующей инструкции)
                if k not in self.labels:
                    raise ValueError(f"undefined label {k!r} at insn #{pos}")
                resolved = self.labels[k] - (pos + 1)
                if resolved < 0 or resolved > 0xFFFFFFFF:
                    raise ValueError(f"JA out of range at insn #{pos}: {resolved}")
                k = resolved
            out += _SOCK_FILTER.pack(ins.code, jt, jf, int(k) & 0xFFFFFFFF)
        return bytes(out)

    def __len__(self) -> int:
        return len(self.insns)


def _is_jmp(code: int) -> bool:
    return (code & 0x07) == BPF_JMP


def insn_count(program: bytes) -> int:
    return len(program) // _SOCK_FILTER.size


def disassemble(program: bytes) -> list[str]:
    """Минимальный дизассемблер для отладки/верификации профиля."""
    out = []
    n = insn_count(program)
    for i in range(n):
        code, jt, jf, k = _SOCK_FILTER.unpack_from(program, i * _SOCK_FILTER.size)
        cls = code & 0x07
        if cls == BPF_LD:
            out.append(f"{i:04d}: ld [{k}]")
        elif cls == BPF_ALU:
            out.append(f"{i:04d}: and #{k:#x}")
        elif cls == BPF_RET:
            action = {
                SECCOMP_RET_ALLOW: "ALLOW",
                SECCOMP_RET_KILL_PROCESS: "KILL_PROCESS",
                SECCOMP_RET_KILL_THREAD: "KILL_THREAD",
                SECCOMP_RET_TRAP: "TRAP",
                SECCOMP_RET_LOG: "LOG",
            }.get(k & SECCOMP_RET_ACTION_FULL, f"ERRNO({k & 0xFFFF})"
                  if (k & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_ERRNO else f"{k:#x}")
            out.append(f"{i:04d}: ret {action}")
        elif cls == BPF_JMP:
            op = code & 0xF0
            name = {BPF_JEQ: "jeq", BPF_JGT: "jgt", BPF_JSET: "jset", BPF_JA: "jmp"}.get(op, f"jmp{op:#x}")
            if op == BPF_JA:
                out.append(f"{i:04d}: {name} -> {i + 1 + k}")
            else:
                out.append(f"{i:04d}: {name} #{k:#x}, jt->{i + 1 + jt}, jf->{i + 1 + jf}")
        else:
            out.append(f"{i:04d}: raw {code:#x} {jt} {jf} {k:#x}")
    return out
