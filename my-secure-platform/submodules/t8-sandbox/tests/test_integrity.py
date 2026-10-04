"""Тесты измерения целостности (F-E-06): SHA-256, Merkle-root, SBOM-сверка."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ztbootstrap.integrity import (
    compare_with_sbom,
    merkle_root,
    model_weights_merkle_root,
    sha256_file,
    IntegrityReport,
    IntegrityError,
)


def test_sha256_file_matches_hashlib(tmp_path: Path):
    f = tmp_path / "blob.bin"
    payload = bytes(range(256)) * 100
    f.write_bytes(payload)
    assert sha256_file(f) == hashlib.sha256(payload).hexdigest()


def test_sha256_unreadable_marker(tmp_path: Path):
    out = sha256_file(tmp_path / "nope.bin")
    assert out.startswith("UNREADABLE:")


def test_merkle_root_known_construction():
    h = hashlib.sha256
    ha, hb, hc, hd = (h(x).digest() for x in (b"a", b"b", b"c", b"d"))
    ab = h(ha + hb).digest()
    cd = h(hc + hd).digest()
    assert merkle_root([ha, hb, hc, hd]) == h(ab + cd).hexdigest()


def test_merkle_root_odd_duplicates_last():
    h = hashlib.sha256
    ha, hb, hc = (h(x).digest() for x in (b"a", b"b", b"c"))
    ab = h(ha + hb).digest()
    cc = h(hc + hc).digest()   # нечётный уровень дублирует последний лист
    assert merkle_root([ha, hb, hc]) == h(ab + cc).hexdigest()


def test_merkle_root_single_and_empty():
    single = hashlib.sha256(b"x").digest()
    assert merkle_root([single]) == single.hex()
    empty_leaf = hashlib.sha256(b"").digest()
    assert merkle_root([]) == empty_leaf.hex()


def test_model_weights_merkle_root(tmp_path: Path):
    w1 = tmp_path / "w1.bin"
    w2 = tmp_path / "w2.bin"
    w1.write_bytes(b"weights-1")
    w2.write_bytes(b"weights-2")
    root = model_weights_merkle_root([w2, w1])  # порядок не важен
    root2 = model_weights_merkle_root([w1, w2])
    assert root == root2
    expect = merkle_root([
        bytes.fromhex(sha256_file(str(w1))),
        bytes.fromhex(sha256_file(str(w2))),
    ])
    assert root == expect


def test_model_weights_missing_file_raises(tmp_path: Path):
    with pytest.raises(IntegrityError, match="unreadable"):
        model_weights_merkle_root([tmp_path / "absent.bin"])


def _report(**kw) -> IntegrityReport:
    base = dict(interpreter_path="/usr/bin/python3.11",
                interpreter_sha256="aa" * 32,
                libraries=[{"path": "/lib/libc.so.6", "sha256": "bb" * 32}],
                model_weights_merkle_root="cc" * 32)
    base.update(kw)
    return IntegrityReport(**base)


def test_sbom_compare_all_match():
    sbom = {
        "interpreter_sha256": "aa" * 32,
        "libraries": {"/lib/libc.so.6": "bb" * 32},
        "model_weights_merkle_root": "cc" * 32,
    }
    rep = _report()
    assert compare_with_sbom(rep, sbom) == []
    assert rep.matches_sbom


def test_sbom_detects_extra_library():
    """AC-05: подмена/добавление .so → несовпадение с эталоном."""
    sbom = {"libraries": {"/lib/libc.so.6": "bb" * 32}}
    rep = _report(libraries=[
        {"path": "/lib/libc.so.6", "sha256": "bb" * 32},
        {"path": "/tmp/evil.so", "sha256": "dd" * 32},
    ])
    mismatches = compare_with_sbom(rep, sbom)
    assert any("not in SBOM" in m and "/tmp/evil.so" in m for m in mismatches)
    assert not rep.matches_sbom


def test_sbom_detects_hash_mismatch():
    sbom = {"libraries": {"/lib/libc.so.6": "ff" * 32}}
    rep = _report()
    mismatches = compare_with_sbom(rep, sbom)
    assert any("hash mismatch" in m for m in mismatches)


def test_sbom_detects_interpreter_swap():
    sbom = {"interpreter_sha256": "99" * 32}
    rep = _report()
    mismatches = compare_with_sbom(rep, sbom)
    assert any("interpreter" in m for m in mismatches)


def test_sbom_detects_missing_expected_library():
    sbom = {"libraries": {"/lib/libc.so.6": "bb" * 32,
                          "/lib/libm.so.6": "ee" * 32}}
    rep = _report()
    mismatches = compare_with_sbom(rep, sbom)
    assert any("missing at runtime" in m for m in mismatches)


def test_sbom_empty_expectations_neutral():
    rep = _report()
    assert compare_with_sbom(rep, {}) == []
