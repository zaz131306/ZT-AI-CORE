"""Работа с /proc/self/maps: baseline snapshot и post-SECCOMP сверка (F-E-07).

Чек-лист §2:
  * Шаг 3 — «Baseline snapshot: сохранить /proc/self/maps как baseline»;
  * Шаг 6 — «Сверка /proc/self/maps с baseline. Любое расхождение → SIGKILL».

Сверка выполняется по МНОЖЕСТВУ ОТОБРАЖЁННЫХ ФАЙЛОВ (path set) и по хэшу
нормализованного текста: новое отображение .so/.pyd (lazy-загрузка после
SECCOMP) меняет path set → расхождение. Анонимные области (куча, стек,
mmap без файла) нормализуются, чтобы аллокации рантайма не давали ложных
срабатываний; их полный контроль обеспечивает запрет mmap(PROT_EXEC)
в SECCOMP-фильтре.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

MAPS_PATH = Path("/proc/self/maps")

# Eager-import хэш-библиотеки: ВСЕ импорты должны произойти ДО baseline
# snapshot /proc/self/maps (F-E-07), иначе ленивая загрузка blake3 .so
# будет легитимно поймана сверкой Шага 6 как дрейф.
try:  # pragma: no cover - зависит от окружения
    import blake3 as _blake3  # type: ignore

    _HAS_BLAKE3 = True
except ImportError:  # pragma: no cover
    _blake3 = None
    _HAS_BLAKE3 = False

_MAPS_LINE_RE = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+"
    r"(?P<perms>[rwxps-]{4})\s+"
    r"(?P<offset>[0-9a-f]+)\s+"
    r"(?P<dev>\S+)\s+"
    r"(?P<inode>\d+)\s*"
    r"(?P<path>.*)$")

# Специальные псевдо-файлы, которые легально меняются между снапшотами.
_VOLATILE_PATHS = frozenset({"", "[heap]", "[stack]", "[vvar]", "[vsyscall]",
                             "[vvar_vclock]", "[anon]"})


@dataclass(frozen=True)
class MapEntry:
    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    path: str

    @property
    def is_file_backed(self) -> bool:
        return bool(self.path) and not self.path.startswith("[")

    @property
    def is_executable(self) -> bool:
        return "x" in self.perms


def parse_maps(text: str) -> list[MapEntry]:
    """Парсинг содержимого /proc/self/maps (тестируемо на текстах)."""
    entries: list[MapEntry] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        m = _MAPS_LINE_RE.match(line)
        if not m:
            raise ValueError(f"unparsable maps line: {line!r}")
        entries.append(MapEntry(
            start=int(m.group("start"), 16),
            end=int(m.group("end"), 16),
            perms=m.group("perms"),
            offset=int(m.group("offset"), 16),
            dev=m.group("dev"),
            inode=int(m.group("inode")),
            path=m.group("path").strip(),
        ))
    return entries


def read_maps(pid: int | None = None) -> str:
    path = MAPS_PATH if pid is None else Path(f"/proc/{pid}/maps")
    return path.read_text(encoding="ascii", errors="replace")


def file_paths(entries: list[MapEntry]) -> frozenset[str]:
    """Множество file-backed путей отображений (включая .so/.pyd)."""
    return frozenset(e.path for e in entries if e.is_file_backed)


def shared_objects(entries: list[MapEntry]) -> list[str]:
    """Список загруженных разделяемых библиотек (.so*), отсортированный."""
    sos = {e.path for e in entries
           if e.is_file_backed and ".so" in os.path.basename(e.path)}
    return sorted(sos)


def normalize_maps(text: str) -> str:
    """Нормализация для хэша: только file-backed пути и их права.

    Анонимные области и адреса исключаются (меняются легально); файловый
    набор и права отображений — инвариант, нарушение которого означает
    lazy-загрузку кода после SECCOMP.
    """
    lines = []
    for e in parse_maps(text):
        if e.path in _VOLATILE_PATHS:
            continue
        lines.append(f"{e.path}|{e.perms}|{e.dev}|{e.inode}")
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def maps_hash(text: str) -> str:
    """BLAKE3-хэш нормализованного maps (fallback blake2b в dev без blake3).

    Библиотека blake3 импортирована на уровне модуля (eager) — сам вызов
    хэша не выполняет lazy-загрузку .so после baseline snapshot.
    """
    normalized = normalize_maps(text).encode("utf-8")
    if _HAS_BLAKE3:
        return _blake3.blake3(normalized).hexdigest()
    import hashlib

    return "blake2b:" + hashlib.blake2b(normalized, digest_size=32).hexdigest()


@dataclass(frozen=True)
class MapsDiff:
    added_paths: frozenset[str]
    removed_paths: frozenset[str]
    perms_changed: tuple[str, ...]
    hash_match: bool

    @property
    def clean(self) -> bool:
        return (self.hash_match and not self.added_paths
                and not self.removed_paths and not self.perms_changed)


def diff_maps(baseline_text: str, current_text: str) -> MapsDiff:
    """Сверка baseline и текущего maps (Шаг 6). Любое расхождение — не clean."""
    base_entries = parse_maps(baseline_text)
    cur_entries = parse_maps(current_text)
    base_paths = file_paths(base_entries)
    cur_paths = file_paths(cur_entries)

    def perms_map(entries: list[MapEntry]) -> dict[str, str]:
        out: dict[str, str] = {}
        for e in entries:
            if e.path in _VOLATILE_PATHS:
                continue
            merged = out.get(e.path, "----")
            out[e.path] = "".join(
                c1 if c1 != "-" else c2 for c1, c2 in zip(merged, e.perms))
        return out

    base_perms = perms_map(base_entries)
    cur_perms = perms_map(cur_entries)
    changed = tuple(sorted(
        p for p in base_perms.keys() & cur_perms.keys()
        if base_perms[p] != cur_perms[p]))
    return MapsDiff(
        added_paths=cur_paths - base_paths,
        removed_paths=base_paths - cur_paths,
        perms_changed=changed,
        hash_match=maps_hash(baseline_text) == maps_hash(current_text),
    )
