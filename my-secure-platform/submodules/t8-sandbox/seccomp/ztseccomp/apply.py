"""Применение SECCOMP-фильтра и capability drop через prctl(2)/seccomp(2).

Реализует F-E-09 (Capability Drop) и Шаг 5 Bootstrap Sequence:
  1. ``prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)``;
  2. ``prctl(PR_CAPBSET_DROP, cap)`` для каждого cap в bounding set;
  3. проверка ``/proc/self/status``: CapEff == CapPrm == CapInh == 0,
     NoNewPrivs == 1 — иначе ``exit(1)``;
  4. только затем ``prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)``.

Используется glibc (F-E-08). Все вызовы — через ctypes без внешних зависимостей.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno as errno_mod
import os
import struct
from dataclasses import dataclass
from pathlib import Path

# Eager-import blake3 (F-E-07): хэш BPF-программы не должен вызывать
# lazy-загрузку .so после baseline snapshot.
try:  # pragma: no cover - зависит от окружения
    import blake3 as _blake3  # type: ignore

    _HAS_BLAKE3 = True
except ImportError:  # pragma: no cover
    _blake3 = None
    _HAS_BLAKE3 = False


# --- prctl options (include/uapi/linux/prctl.h) -------------------------------
PR_SET_SECCOMP = 22
PR_GET_SECCOMP = 21
PR_CAPBSET_READ = 23
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39

SECCOMP_MODE_DISABLED = 0
SECCOMP_MODE_STRICT = 1
SECCOMP_MODE_FILTER = 2

STATUS_PATH = Path("/proc/self/status")
CAP_LAST_CAP_PATH = Path("/proc/sys/kernel/cap_last_cap")

# Максимально возможный cap (fallback, если /proc/sys/kernel/cap_last_cap
# недоступен): CAP_CHECKPOINT_RESTORE = 40 (Linux 5.9+).
_CAP_LAST_CAP_FALLBACK = 40


class SeccompError(RuntimeError):
    """Ошибка применения SECCOMP/capability drop."""


@dataclass(frozen=True)
class SockFilter(ctypes.Structure):
    """struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }"""

    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class SockFprog(ctypes.Structure):
    """struct sock_fprog { __u16 len; struct sock_filter *filter; }"""

    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


def _libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c") or "libc.so.6"
    lib = ctypes.CDLL(name, use_errno=True)
    lib.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    lib.prctl.restype = ctypes.c_int
    return lib


_LIBC: ctypes.CDLL | None = None


def libc() -> ctypes.CDLL:
    global _LIBC
    if _LIBC is None:
        _LIBC = _libc()
    return _LIBC


def _prctl(option: int, *args: int) -> int:
    lib = libc()
    ctypes.set_errno(0)
    padded = list(args) + [0] * (4 - len(args))
    rc = lib.prctl(option, *[ctypes.c_ulong(a & 0xFFFFFFFFFFFFFFFF) for a in padded[:4]])
    if rc != 0:
        err = ctypes.get_errno()
        raise SeccompError(
            f"prctl({option}, {args[:len(args)]}) failed: "
            f"{errno_mod.errorcode.get(err, err)} ({err})")
    return rc


# ----------------------------------------------------------------------------
# /proc/self/status: capabilities
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class CapsStatus:
    cap_inh: int
    cap_prm: int
    cap_eff: int
    cap_bnd: int
    cap_amb: int
    no_new_privs: int
    seccomp: int | None  # поле Seccomp: присутствует не во всех ядрах

    @property
    def all_cleared(self) -> bool:
        """Требование F-E-09: CapEff == CapPrm == CapInh == 0, NoNewPrivs == 1."""
        return (self.cap_eff == 0 and self.cap_prm == 0 and self.cap_inh == 0
                and self.no_new_privs == 1)


def read_caps_status(status_text: str | None = None) -> CapsStatus:
    """Парсинг /proc/self/status (тестируемо: можно передать текст напрямую)."""
    if status_text is None:
        status_text = STATUS_PATH.read_text(encoding="ascii", errors="replace")
    fields: dict[str, str] = {}
    for line in status_text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()

    def hexval(name: str) -> int:
        raw = fields.get(name, "0")
        return int(raw, 16)

    def intval(name: str, default: int = 0) -> int:
        raw = fields.get(name)
        return int(raw) if raw is not None else default

    seccomp = fields.get("Seccomp")
    return CapsStatus(
        cap_inh=hexval("CapInh"),
        cap_prm=hexval("CapPrm"),
        cap_eff=hexval("CapEff"),
        cap_bnd=hexval("CapBnd"),
        cap_amb=hexval("CapAmb"),
        no_new_privs=intval("NoNewPrivs"),
        seccomp=int(seccomp) if seccomp is not None else None,
    )


def cap_last_cap() -> int:
    try:
        return int(CAP_LAST_CAP_PATH.read_text().strip())
    except (OSError, ValueError):
        return _CAP_LAST_CAP_FALLBACK


def bounding_set_caps() -> list[int]:
    """Список cap, присутствующих в bounding set (PR_CAPBSET_READ)."""
    present = []
    for cap in range(0, cap_last_cap() + 1):
        try:
            rc = _prctl(PR_CAPBSET_READ, cap)
        except SeccompError:
            continue
        if rc == 1:
            present.append(cap)
    return present


# ----------------------------------------------------------------------------
# Capability drop (F-E-09, Шаг 4)
# ----------------------------------------------------------------------------

def set_no_new_privs() -> None:
    """prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) — обязателен до unprivileged-фильтра."""
    _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def drop_bounding_capabilities(verbose: bool = False) -> list[int]:
    """PR_CAPBSET_DROP для каждого cap в bounding set. Возвращает сброшенные."""
    dropped: list[int] = []
    for cap in bounding_set_caps():
        _prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)
        dropped.append(cap)
        if verbose:
            print(f"[ztseccomp] PR_CAPBSET_DROP cap={cap}")
    return dropped


# --- capset(2): обнуление effective/permitted/inheritable ----------------------
# В контексте bwrap (F-E-01) CapEff уже равен 0; вне песочницы (dev/тесты)
# PR_CAPBSET_DROP не очищает effective-множество — для гарантированного
# выполнения проверки F-E-09 (CapEff==CapPrm==CapInh==0) обнуляем наборы
# через capset(2) (glibc wrapper).

_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def clear_capability_sets() -> bool:
    """capset(2): обнулить CapEff/CapPrm/CapInh текущего процесса.

    :returns: True при успехе; False если вызов недоступен/отклонён
              (в bwrap-контексте наборы и так пусты — это не ошибка).
    """
    lib = libc()
    try:
        capset = lib.capset
    except AttributeError:
        return False
    capset.argtypes = [ctypes.POINTER(_CapHeader), ctypes.POINTER(_CapData)]
    capset.restype = ctypes.c_int
    header = _CapHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=0)
    data = (_CapData * 2)()  # v3: два слова по 32 бита = 64 capabilities, все нули
    ctypes.set_errno(0)
    rc = capset(ctypes.byref(header), ctypes.cast(data, ctypes.POINTER(_CapData)))
    if rc != 0:
        err = ctypes.get_errno()
        if err == errno_mod.EPERM:
            return False
        raise SeccompError(
            f"capset(2) failed: {errno_mod.errorcode.get(err, err)} ({err})")
    return True


def verify_capability_drop() -> CapsStatus:
    """Проверка после Шага 4. SeccompError, если требования F-E-09 не выполнены."""
    status = read_caps_status()
    if not status.all_cleared:
        raise SeccompError(
            "capability drop verification failed: "
            f"CapEff={status.cap_eff:#018x} CapPrm={status.cap_prm:#018x} "
            f"CapInh={status.cap_inh:#018x} NoNewPrivs={status.no_new_privs} "
            "(требуется: CapEff==CapPrm==CapInh==0, NoNewPrivs==1)")
    return status


# ----------------------------------------------------------------------------
# Применение фильтра (Шаг 5)
# ----------------------------------------------------------------------------

def apply_bpf_filter(program: bytes) -> int:
    """prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog).

    :param program: байты sock_filter[] (кратны 8).
    :returns: число инструкций.
    """
    if len(program) == 0 or len(program) % 8 != 0:
        raise SeccompError(f"invalid BPF program length: {len(program)}")
    n = len(program) // 8
    if n > 4096:
        raise SeccompError(f"BPF program too large: {n} > 4096")

    InsnArray = SockFilter * n
    insns = InsnArray()
    ctypes.memmove(insns, program, len(program))

    prog = SockFprog()
    prog.len = n
    prog.filter = ctypes.cast(insns, ctypes.POINTER(SockFilter))

    # NO_NEW_PRIVS — предусловие установки фильтра непривилегированным процессом.
    status = read_caps_status()
    if status.no_new_privs != 1:
        set_no_new_privs()

    lib = libc()
    ctypes.set_errno(0)
    rc = lib.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                   ctypes.addressof(prog), 0, 0)
    if rc != 0:
        err = ctypes.get_errno()
        raise SeccompError(
            f"prctl(PR_SET_SECCOMP, FILTER) failed: "
            f"{errno_mod.errorcode.get(err, err)} ({err})")
    # держим ссылку на буфер до конца вызова (защита от GC)
    ctypes.keepalive = getattr(ctypes, "keepalive", None)
    _ = insns
    return n


def seccomp_mode() -> int:
    """Текущий режим seccomp (0 disabled / 1 strict / 2 filter)."""
    return _prctl(PR_GET_SECCOMP)


def is_seccomp_available() -> bool:
    """Доступен ли seccomp в данном ядре/контейнере (без применения)."""
    try:
        _prctl(PR_GET_SECCOMP)
        return True
    except SeccompError:
        return False


def pid_in_own_ns() -> int:
    """PID в собственном PID namespace (NSpid первая запись) — для диагностики."""
    try:
        text = STATUS_PATH.read_text()
    except OSError:
        return os.getpid()
    for line in text.splitlines():
        if line.startswith("NSpid:"):
            parts = line.split()[1:]
            return int(parts[0]) if parts else os.getpid()
    return os.getpid()


def program_blake3(program: bytes) -> str:
    """BLAKE3-хэш скомпилированной BPF-программы (целостность профиля).

    Использует пакет blake3, если он установлен; иначе — hashlib.blake2b
    (только для dev-диагностики; в prod blake3 обязателен — Приложение Б).
    """
    if _HAS_BLAKE3:
        return _blake3.blake3(program).hexdigest()
    import hashlib

    return "blake2b:" + hashlib.blake2b(program, digest_size=32).hexdigest()


def pack_filter_to_file(program: bytes, path: str | os.PathLike[str]) -> None:
    """Сохранить sock_filter[] в файл (артефакт scripts/build-sec-profile.sh)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack("<4sII", b"ZTSB", 1, len(program) // 8)
    p.write_bytes(header + program)
    p.chmod(0o644)


def load_filter_from_file(path: str | os.PathLike[str]) -> bytes:
    """Загрузить sock_filter[] из артефакта build-sec-profile.sh."""
    raw = Path(path).read_bytes()
    magic, version, count = struct.unpack("<4sII", raw[:12])
    if magic != b"ZTSB" or version != 1:
        raise SeccompError(f"bad filter artifact header: {magic!r} v{version}")
    program = raw[12:]
    if len(program) != count * 8:
        raise SeccompError(
            f"filter artifact truncated: {len(program)} != {count} * 8")
    return program
