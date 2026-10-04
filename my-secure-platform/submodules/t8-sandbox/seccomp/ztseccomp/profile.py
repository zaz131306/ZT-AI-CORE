"""Компиляция JSON-профиля SECCOMP (Приложение В ТЗ) в classic BPF.

Семантика профиля (first-match-wins):
  1. ``arch``-guard: ``seccomp_data.arch`` обязан совпасть с целевой
     архитектурой, иначе — ``SCMP_ACT_KILL_PROCESS`` (защита от x32-ABI).
  2. Правила ``syscalls[]`` с ``args`` вычисляются ПО ПОРЯДКУ следования в
     JSON: nr ∈ ``names`` И все матчеры истинны → действие; иначе оценка
     продолжается следующими правилами.
  3. Затем правила БЕЗ аргументов (линейный матчинг nr, сгруппированный по
     действиям в порядке JSON).
  4. Ни одно правило не совпало → ``defaultAction``.

Поддерживаемые матчеры: ``SCMP_CMP_EQ``, ``SCMP_CMP_NE``, ``SCMP_CMP_MASKED_EQ``.
64-битные аргументы проверяются двумя 32-битными словами (little-endian):
младшее — ``16+8*i``, старшее — ``16+8*i+4``.

Ограничение cBPF: условные переходы (jt/jf) — 8 бит и только ВПЕРЁД.
Компоновка программы это учитывает: блоки проверки аргументов встроены
inline сразу за своей цепочкой сравнений (переходы «промах» ведут только
вперёд), а длинный whitelist разбивается на группы ≤ 64 имён, где каждое
``jeq`` прыгает на соседний stub-``ret`` (дистанция ≤ 2*64+1 < 255).
"""
from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Union

from . import _tables_gen
from .bpf import (
    OFF_ARCH,
    OFF_NR,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_LOG,
    SECCOMP_RET_TRAP,
    Assembler,
    arg_hi_offset,
    arg_lo_offset,
)

AUDIT_ARCH = {
    "x86_64": _tables_gen.AUDIT_ARCH_X86_64,
    "aarch64": _tables_gen.AUDIT_ARCH_AARCH64,
}

ACTION_VALUES = {
    "SCMP_ACT_KILL_PROCESS": SECCOMP_RET_KILL_PROCESS,
    "SCMP_ACT_KILL_THREAD": SECCOMP_RET_KILL_THREAD,
    "SCMP_ACT_TRAP": SECCOMP_RET_TRAP,
    "SCMP_ACT_LOG": SECCOMP_RET_LOG,
    "SCMP_ACT_ALLOW": SECCOMP_RET_ALLOW,
}

OP_VALUES = {
    "SCMP_CMP_EQ": "eq",
    "SCMP_CMP_NE": "ne",
    "SCMP_CMP_MASKED_EQ": "masked_eq",
}

# Максимум имён в группе линейного матчинга (jeq → stub ≤ 2*G+1 ≤ 255).
_MATCH_GROUP = 64


class ProfileError(ValueError):
    """Ошибка валидации/компиляции JSON-профиля."""


def native_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    raise ProfileError(f"unsupported architecture: {machine!r} (ожидаются x86_64/aarch64)")


def _as_int(v: Any) -> int:
    if isinstance(v, bool):
        raise ProfileError("bool is not a valid integer argument")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    raise ProfileError(f"cannot parse integer from {v!r}")


@dataclass(frozen=True)
class ArgMatcher:
    """Матчер одного 64-битного аргумента syscall."""

    index: int
    op: str            # "eq" | "ne" | "masked_eq"
    value: int
    mask: int = 0xFFFFFFFFFFFFFFFF

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "ArgMatcher":
        try:
            index = int(raw["index"])
            op_name = str(raw.get("op", "SCMP_CMP_EQ"))
            value = _as_int(raw["value"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProfileError(f"invalid arg matcher {raw!r}: {exc}") from exc
        if not 0 <= index <= 5:
            raise ProfileError(f"arg index out of range 0..5: {index}")
        if op_name not in OP_VALUES:
            raise ProfileError(
                f"unsupported arg op {op_name!r}; allowed: {sorted(OP_VALUES)}")
        mask = 0xFFFFFFFFFFFFFFFF
        if op_name == "SCMP_CMP_MASKED_EQ":
            mask = _as_int(raw.get("mask", 0xFFFFFFFFFFFFFFFF))
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ProfileError(f"arg value out of u64 range: {value}")
        if not 0 <= mask <= 0xFFFFFFFFFFFFFFFF:
            raise ProfileError(f"arg mask out of u64 range: {mask}")
        return cls(index=index, op=OP_VALUES[op_name], value=value, mask=mask)


@dataclass(frozen=True)
class ProfileRule:
    names: tuple[str, ...]
    action: int
    args: tuple[ArgMatcher, ...] = ()
    comment: str = ""

    @property
    def action_name(self) -> str:
        return _action_str(self.action)


@dataclass
class CompileReport:
    arch: str
    instruction_count: int = 0
    rules_total: int = 0
    rules_compiled: int = 0
    skipped_names: list[str] = field(default_factory=list)
    default_action: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "instruction_count": self.instruction_count,
            "rules_total": self.rules_total,
            "rules_compiled": self.rules_compiled,
            "skipped_names": sorted(set(self.skipped_names)),
            "default_action": self.default_action,
            "notes": self.notes,
        }


# ----------------------------------------------------------------------------
# Загрузка и валидация JSON-профиля
# ----------------------------------------------------------------------------

def load_profile(path: Union[str, Path]) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_profile_schema(data)
    return data


def _is_errno_action(action: Any) -> bool:
    return isinstance(action, str) and action.startswith("SCMP_ACT_ERRNO")


def _parse_action(raw: Any, ctx: dict[str, Any]) -> int:
    if raw in ACTION_VALUES:
        return ACTION_VALUES[raw]
    if _is_errno_action(raw):
        errno = int(ctx.get("errnoRet", 1))
        if not 0 <= errno <= 0xFFFF:
            raise ProfileError(f"errnoRet out of range: {errno}")
        return SECCOMP_RET_ERRNO | errno
    raise ProfileError(f"unknown action {raw!r}")


def validate_profile_schema(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ProfileError("profile root must be an object")
    default = data.get("defaultAction")
    if default not in ACTION_VALUES and not _is_errno_action(default):
        raise ProfileError(f"missing/invalid defaultAction: {default!r}")
    syscalls = data.get("syscalls")
    if not isinstance(syscalls, list) or not syscalls:
        raise ProfileError("profile must contain non-empty 'syscalls' list")
    for i, entry in enumerate(syscalls):
        if not isinstance(entry, dict):
            raise ProfileError(f"syscalls[{i}] must be an object")
        names = entry.get("names")
        if not isinstance(names, list) or not names or \
                not all(isinstance(n, str) for n in names):
            raise ProfileError(f"syscalls[{i}].names must be a non-empty list of strings")
        action = entry.get("action")
        if action not in ACTION_VALUES and not _is_errno_action(action):
            raise ProfileError(f"syscalls[{i}].action invalid: {action!r}")
        for j, arg in enumerate(entry.get("args") or []):
            if not isinstance(arg, dict):
                raise ProfileError(f"syscalls[{i}].args[{j}] must be an object")
            ArgMatcher.parse(arg)


def parse_rules(data: dict[str, Any]) -> tuple[list[ProfileRule], int]:
    default_action = _parse_action(data["defaultAction"], data)
    rules: list[ProfileRule] = []
    for entry in data["syscalls"]:
        action = _parse_action(entry["action"], entry)
        args = tuple(ArgMatcher.parse(a) for a in (entry.get("args") or []))
        rules.append(ProfileRule(
            names=tuple(entry["names"]),
            action=action,
            args=args,
            comment=str(entry.get("comment", ""))[:200],
        ))
    return rules, default_action


# ----------------------------------------------------------------------------
# Компиляция в BPF
# ----------------------------------------------------------------------------

def compile_profile(profile: Union[str, Path, dict[str, Any]],
                    arch: Union[str, None] = None) -> tuple[bytes, CompileReport]:
    """Скомпилировать профиль в байты программы ``sock_filter[]``.

    :param profile: путь к JSON-профилю или загруженный dict.
    :param arch: "x86_64" | "aarch64" | None (нативная архитектура).
    :returns: (программа, отчёт компиляции).
    :raises ProfileError: профиль невалиден или не компилируется.
    """
    data = profile if isinstance(profile, dict) else load_profile(profile)
    target_arch = arch or native_arch()
    if target_arch not in AUDIT_ARCH:
        raise ProfileError(f"unsupported arch {target_arch!r}")
    table = _tables_gen.SYSCALL_TABLES[target_arch]

    rules, default_action = parse_rules(data)
    report = CompileReport(arch=target_arch, rules_total=len(rules),
                           default_action=_action_str(default_action))

    asm = Assembler()
    uid = {"n": 0}

    def tag(prefix: str) -> str:
        uid["n"] += 1
        return f"{prefix}{uid['n']}"

    # -- 0. arch-guard ---------------------------------------------------------
    # insn0: ld arch; insn1: jeq → (true) insn3=dispatch / (false) insn2=ret KILL
    asm.ld_abs(OFF_ARCH)
    asm.jeq(AUDIT_ARCH[target_arch], jt=1, jf=0)
    asm.ret(SECCOMP_RET_KILL_PROCESS)

    # -- 1. dispatch: загрузка номера syscall -----------------------------------
    asm.label("dispatch")
    asm.ld_abs(OFF_NR)

    # -- 2. arg-правила: interleaved forward-only компоновка ---------------------
    #
    #   jeq nr_a → B_i        (для каждого имени правила i)
    #   jeq nr_b → B_i
    #   jmp C_i               (nr не из правила i — следующее правило)
    # B_i: <проверка args>
    #      ok   → ret action_i
    #      miss → jmp C_i     (правило не совпало — оценка продолжается)
    # C_i: <правило i+1 ...>
    #
    arg_rules_compiled = 0
    for idx, rule in enumerate(rules):
        if not rule.args:
            continue
        pairs = []
        for name in rule.names:
            if name not in table:
                report.skipped_names.append(name)
                continue
            pairs.append((name, table[name]))
        if not pairs:
            report.notes.append(
                f"rule #{idx} ({'/'.join(rule.names)}): имена отсутствуют в ABI "
                f"{target_arch} — правило пропущено")
            continue
        block = tag("argblk_")
        cont = tag("argcont_")
        for _name, nr in pairs:
            asm.jeq(nr, jt=block, jf=0)
        asm.jmp(cont)
        asm.label(block)
        _emit_arg_checks(asm, rule, ok_action_ret=True, cont=cont, tag=tag)
        asm.label(cont)
        # КРИТИЧНО: блок аргументов перезаписывает аккумулятор (ld args),
        # поэтому в точке продолжения номер syscall загружается заново —
        # иначе последующие jeq nr сравнивались бы со значением аргумента
        # (алиасинг аргумент↔nr = обход фильтра).
        asm.ld_abs(OFF_NR)
        arg_rules_compiled += 1

    # -- 3. plain-правила (без args): линейные группы по действиям ---------------
    asm.label("plain_dispatch")
    # Точка входа plain-матчинга достижима переходом из arg-блоков (miss),
    # где аккумулятор содержит значение аргумента — перезагружаем nr.
    asm.ld_abs(OFF_NR)
    plain_by_action: dict[int, list[int]] = {}
    plain_order: list[int] = []
    plain_rules_compiled = 0
    # Детектор коллизий: один и тот же nr в plain-правилах с РАЗНЫМИ действиями
    # — почти всегда ошибка профиля (например, compat-алиас имени: __NR_mmap2
    # в asm-generic совпадает с __NR_mmap на aarch64). Такая коллизия молча
    # меняла бы семантику whitelist, поэтому сборка останавливается.
    nr_owners: dict[int, tuple[int, str]] = {}
    for rule in rules:
        if rule.args:
            continue
        for name in rule.names:
            if name not in table:
                continue
            nr = table[name]
            prev = nr_owners.get(nr)
            if prev is not None and prev[0] != rule.action:
                raise ProfileError(
                    f"plain-rule collision: syscall nr {nr} on {target_arch} "
                    f"claimed by {prev[1]!r} (action {_action_str(prev[0])}) and "
                    f"{name!r} (action {rule.action_name}) — исправьте профиль "
                    f"(возможный compat-алиас имени в ABI {target_arch})")
            nr_owners[nr] = (rule.action, name)
    for rule in rules:
        if rule.args:
            continue
        nrs = []
        for name in rule.names:
            if name not in table:
                report.skipped_names.append(name)
                continue
            nrs.append(table[name])
        if not nrs:
            report.notes.append(f"rule (action={rule.action_name}): пропущено — "
                                f"нет имён в ABI {target_arch}")
            continue
        plain_rules_compiled += 1
        if rule.action not in plain_by_action:
            plain_by_action[rule.action] = []
            plain_order.append(rule.action)
        for nr in nrs:
            if nr not in plain_by_action[rule.action]:
                plain_by_action[rule.action].append(nr)

    # Цепочки действий: первая по JSON-порядку цепочка оценивается первой;
    # её промах уходит на следующую цепочку, последняя — на default.
    labels = [f"plain_chain_{i}" for i in range(len(plain_order))] + ["plain_default"]
    for order_i, action in enumerate(plain_order):
        asm.label(labels[order_i])
        _emit_match_groups(asm, sorted(plain_by_action[action]), action,
                           miss=labels[order_i + 1], tag=tag)

    # -- 4. default action -------------------------------------------------------
    asm.label("plain_default")
    asm.ret(default_action)

    program = asm.assemble()
    report.instruction_count = len(asm)
    report.rules_compiled = arg_rules_compiled + plain_rules_compiled
    if report.instruction_count > 4096:
        raise ProfileError(
            f"filter too large: {report.instruction_count} > 4096 инструкций")
    return program, report


def _emit_arg_checks(asm: Assembler, rule: ProfileRule, ok_action_ret: bool,
                     cont: str, tag: Callable[[str], str]) -> None:
    """Проверка всех матчеров правила; ok -> ret action, miss -> jmp cont."""
    for matcher in rule.args:
        nxt = tag("argstep_")
        _emit_matcher(asm, matcher, ok=nxt, fail=cont, tag=tag("argm_"))
        asm.label(nxt)
    if ok_action_ret:
        asm.ret(rule.action)
    else:  # pragma: no cover — зарезервировано для расширяемых действий
        asm.jmp(cont)


def _emit_matcher(asm: Assembler, m: ArgMatcher, ok: str, fail: str, tag: str) -> None:
    """Проверка одного аргумента (64 бит = два 32-битных слова, little-endian)."""
    value_lo = m.value & 0xFFFFFFFF
    value_hi = (m.value >> 32) & 0xFFFFFFFF
    mask_lo = m.mask & 0xFFFFFFFF
    mask_hi = (m.mask >> 32) & 0xFFFFFFFF

    if m.op == "eq":
        asm.ld_abs(arg_hi_offset(m.index))
        asm.jeq(value_hi, jt=0, jf=fail)
        asm.ld_abs(arg_lo_offset(m.index))
        asm.jeq(value_lo, jt=ok, jf=fail)
    elif m.op == "ne":
        # arg != value  <=>  hi != v_hi  OR  (hi == v_hi AND lo != v_lo)
        hi_eq = tag("nehi_")
        asm.ld_abs(arg_hi_offset(m.index))
        asm.jeq(value_hi, jt=hi_eq, jf=ok)     # hi != v_hi -> arg гарантированно != value
        asm.label(hi_eq)
        asm.ld_abs(arg_lo_offset(m.index))
        asm.jeq(value_lo, jt=fail, jf=ok)      # hi == v_hi: lo == v_lo -> промах
    elif m.op == "masked_eq":
        # (arg & mask) == value
        if (m.value & ~m.mask) & 0xFFFFFFFFFFFFFFFF:
            asm.jmp(fail)                      # биты value вне mask -> всегда ложно
            return
        if mask_hi == 0 and mask_lo == 0:
            asm.jmp(ok)                        # (arg & 0) == 0 -> всегда истинно
            return
        if mask_hi:
            asm.ld_abs(arg_hi_offset(m.index))
            asm.and_k(mask_hi)
            asm.jeq(value_hi & mask_hi, jt=0, jf=fail)
        if mask_lo:
            asm.ld_abs(arg_lo_offset(m.index))
            asm.and_k(mask_lo)
            asm.jeq(value_lo & mask_lo, jt=ok, jf=fail)
        else:
            asm.jmp(ok)
    else:  # pragma: no cover — защищено валидацией OP_VALUES
        raise ProfileError(f"unsupported matcher op: {m.op}")


def _emit_match_groups(asm: Assembler, nrs: list[int], action: int,
                       miss: str, tag: Callable[[str], str]) -> None:
    """Линейный матчинг nr группами ≤ _MATCH_GROUP с близкими stub-ретурнами.

    Группа: ``jeq nr_i → stub_i`` (fallthrough — следующее имя); после группы
    ``jmp miss`` (или следующая группа); затем ``stub_i: ret action``.
    """
    if not nrs:
        asm.jmp(miss)
        return
    for g in range(0, len(nrs), _MATCH_GROUP):
        group = nrs[g:g + _MATCH_GROUP]
        stubs: list[str] = []
        for nr in group:
            stub = tag("mstub_")
            asm.jeq(nr, jt=stub, jf=0)
            stubs.append(stub)
        is_last_group = (g + len(group) >= len(nrs))
        target = miss if is_last_group else tag("mgrp_")
        asm.jmp(target)
        for stub in stubs:
            asm.label(stub)
            asm.ret(action)
        if not is_last_group:
            asm.label(target)


def _action_str(action: int) -> str:
    for name, val in ACTION_VALUES.items():
        if val == action:
            return name
    if action & 0xFFFF0000 == SECCOMP_RET_ERRNO:
        return f"SCMP_ACT_ERRNO({action & 0xFFFF})"
    return f"{action:#010x}"
