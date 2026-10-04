"""Тесты /proc/self/maps: парсинг, нормализация, baseline-сверка (F-E-07)."""
from __future__ import annotations

import pytest

from ztbootstrap.maps import (
    diff_maps,
    file_paths,
    maps_hash,
    normalize_maps,
    parse_maps,
    shared_objects,
)

BASE = """55d1a2c00000-55d1a2c02000 r--p 00000000 08:01 1234  /usr/bin/python3.11
55d1a2c02000-55d1a2e00000 r-xp 00002000 08:01 1234  /usr/bin/python3.11
7f3b1c000000-7f3b1c226000 r--p 00000000 08:01 5678  /usr/lib/x86_64-linux-gnu/libc.so.6
7f3b1c226000-7f3b1c39b000 r-xp 00226000 08:01 5678  /usr/lib/x86_64-linux-gnu/libc.so.6
7f3b1d000000-7f3b1d028000 rw-p 00000000 00:00 0     [heap]
7ffd5e2a1000-7ffd5e2c2000 rw-p 00000000 00:00 0     [stack]
7f3b1e000000-7f3b1e035000 rw-p 00000000 00:00 0
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0  [vsyscall]
"""


def test_parse_maps_basic():
    entries = parse_maps(BASE)
    assert len(entries) == 8
    first = entries[0]
    assert first.start == 0x55D1A2C00000
    assert first.perms == "r--p"
    assert first.path == "/usr/bin/python3.11"
    assert first.is_file_backed and not first.is_executable
    assert entries[1].is_executable


def test_parse_maps_rejects_garbage():
    with pytest.raises(ValueError, match="unparsable"):
        parse_maps("not a maps line at all")


def test_anonymous_entries_not_file_backed():
    entries = parse_maps(BASE)
    anon = [e for e in entries if e.path == ""]
    assert anon and not any(e.is_file_backed for e in anon)


def test_shared_objects_extraction():
    sos = shared_objects(parse_maps(BASE))
    assert sos == ["/usr/lib/x86_64-linux-gnu/libc.so.6"]


def test_file_paths_excludes_pseudo():
    paths = file_paths(parse_maps(BASE))
    assert "/usr/bin/python3.11" in paths
    assert "[heap]" not in paths and "[stack]" not in paths


def test_normalize_ignores_heap_stack_anon_addresses():
    # тот же файловый набор, другие адреса кучи/стека → нормализация идентична
    moved = BASE.replace("7f3b1d000000-7f3b1d028000", "7f3b1d100000-7f3b1d999000")
    assert normalize_maps(BASE) == normalize_maps(moved)


def test_maps_hash_stable_and_sensitive():
    assert maps_hash(BASE) == maps_hash(BASE)
    changed = BASE.replace("libc.so.6", "libc.so.7")
    assert maps_hash(BASE) != maps_hash(changed)


def test_diff_clean_identical():
    d = diff_maps(BASE, BASE)
    assert d.clean


def test_diff_detects_new_so():
    """AC-09/F-E-07: ленивая подгрузка .so после SECCOMP обязана детектироваться."""
    injected = BASE + ("7f3b1f000000-7f3b1f021000 r-xp 00000000 08:01 9999"
                       "                     /opt/evil/payload.so\n")
    d = diff_maps(BASE, injected)
    assert not d.clean
    assert "/opt/evil/payload.so" in d.added_paths


def test_diff_detects_removed_so():
    stripped = "\n".join(l for l in BASE.splitlines() if "libc.so.6" not in l)
    d = diff_maps(BASE, stripped)
    assert not d.clean
    assert "/usr/lib/x86_64-linux-gnu/libc.so.6" in d.removed_paths


def test_diff_detects_perms_change():
    """mprotect-подобное изменение прав файлового отображения."""
    escalated = BASE.replace(
        "55d1a2c02000-55d1a2e00000 r-xp",
        "55d1a2c02000-55d1a2e00000 rwxp")
    d = diff_maps(BASE, escalated)
    assert not d.clean
    assert d.perms_changed == ("/usr/bin/python3.11",)


def test_diff_ignores_legit_heap_growth():
    grown = BASE.replace("7f3b1d000000-7f3b1d028000 rw-p 00000000 00:00 0     [heap]",
                         "7f3b1d000000-7f3b1d999000 rw-p 00000000 00:00 0     [heap]")
    d = diff_maps(BASE, grown)
    assert d.clean, "рост [heap] не должен считаться дрейфом"
