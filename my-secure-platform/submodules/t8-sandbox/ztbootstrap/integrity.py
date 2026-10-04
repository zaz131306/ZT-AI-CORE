"""Измерение целостности рантайма D8 (F-E-06, AC-05).

При каждом старте D8 вычисляется и пишется в WORM:
  * SHA-256 хэш интерпретатора;
  * список загруженных .so (из /proc/self/maps) с SHA-256 каждого;
  * хэш весов модели (Merkle-root, SHA-256);
  * BLAKE3 baseline/post-SECCOMP снапшотов /proc/self/maps.

Несовпадение с эталоном из подписанного SBOM → BOOT_FAILSAFE
(политика IMA appraisal).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .maps import maps_hash, read_maps, shared_objects, parse_maps

CHUNK_SIZE = 1 << 20  # 1 MiB для потокового хэширования


class IntegrityError(RuntimeError):
    """Ошибка измерения целостности."""


def sha256_file(path: str | os.PathLike[str]) -> str:
    """SHA-256 файла потоково; недоступные файлы помечаются 'UNREADABLE:<errno>'."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as exc:
        return f"UNREADABLE:{exc.errno}"
    return h.hexdigest()


def merkle_root(leaves: Iterable[bytes]) -> str:
    """SHA-256 Merkle-root (Приложение: F-E-06 — хэш весов модели).

    Пустой набор → SHA-256(b""). Нечётный уровень дублирует последний лист.
    """
    level = [leaf if leaf else hashlib.sha256(b"").digest() for leaf in leaves]
    if not level:
        level = [hashlib.sha256(b"").digest()]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


def model_weights_merkle_root(weights_paths: Iterable[str | os.PathLike[str]]) -> str:
    """Merkle-root по SHA-256 всех файлов весов (детерминированный порядок)."""
    paths = sorted(str(p) for p in weights_paths)
    digests = []
    for p in paths:
        digest_hex = sha256_file(p)
        if digest_hex.startswith("UNREADABLE:"):
            raise IntegrityError(f"weights file unreadable: {p} ({digest_hex})")
        digests.append(bytes.fromhex(digest_hex))
    return merkle_root(digests)


@dataclass
class IntegrityReport:
    """Соответствует sandbox.proto:IntegrityReport."""

    interpreter_path: str
    interpreter_sha256: str
    libraries: list[dict[str, str]] = field(default_factory=list)
    model_weights_merkle_root: str = ""
    maps_baseline_hash: str = ""
    maps_current_hash: str = ""
    matches_sbom: bool = False
    maps_drift_detected: bool = False
    timestamp_unix_ns: int = 0
    sbom_mismatches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interpreter_path": self.interpreter_path,
            "interpreter_sha256": self.interpreter_sha256,
            "libraries": self.libraries,
            "model_weights_merkle_root": self.model_weights_merkle_root,
            "maps_baseline_hash": self.maps_baseline_hash,
            "maps_current_hash": self.maps_current_hash,
            "matches_sbom": self.matches_sbom,
            "maps_drift_detected": self.maps_drift_detected,
            "timestamp_unix_ns": self.timestamp_unix_ns,
            "sbom_mismatches": self.sbom_mismatches,
        }


def collect_runtime_report(
    maps_text: str | None = None,
    weights_paths: Iterable[str] = (),
    interpreter: str | None = None,
    skip_library_hashes: bool = False,
) -> IntegrityReport:
    """Собрать отчёт целостности текущего процесса (F-E-06).

    :param maps_text: текст /proc/self/maps (None — прочитать сейчас).
    :param weights_paths: файлы весов моделей для Merkle-root.
    :param interpreter: путь к интерпретатору (default: sys.executable).
    :param skip_library_hashes: не хэшировать .so (ускорение dev-режима).
    """
    interp = interpreter or sys.executable
    text = maps_text if maps_text is not None else read_maps()
    entries = parse_maps(text)
    libs: list[dict[str, str]] = []
    for path in shared_objects(entries):
        item = {"path": path}
        item["sha256"] = ("" if skip_library_hashes else sha256_file(path))
        libs.append(item)
    return IntegrityReport(
        interpreter_path=interp,
        interpreter_sha256=sha256_file(interp),
        libraries=libs,
        model_weights_merkle_root=(
            model_weights_merkle_root(weights_paths) if weights_paths else ""),
        maps_current_hash=maps_hash(text),
        timestamp_unix_ns=__import__("time").time_ns(),
    )


def load_sbom_reference(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Загрузка эталона SBOM (config/sbom_reference.json)."""
    p = Path(path)
    if not p.exists():
        raise IntegrityError(f"SBOM reference not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"SBOM reference invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise IntegrityError("SBOM reference root must be an object")
    return data


def compare_with_sbom(report: IntegrityReport,
                      sbom: dict[str, Any]) -> list[str]:
    """Сверка отчёта с эталоном SBOM; возвращает список расхождений.

    Этalon-формат (config/sbom_reference.json)::

        {
          "interpreter_sha256": "...",            # опционально
          "libraries": {"path": "sha256", ...},   # разрешённые .so
          "model_weights_merkle_root": "..."      # опционально
        }

    Политика IMA appraisal: ЛЮБОЕ расхождение (лишняя .so, несовпавший хэш)
    → непустой список → BOOT_FAILSAFE.
    """
    mismatches: list[str] = []

    expected_interp = sbom.get("interpreter_sha256")
    if expected_interp and report.interpreter_sha256 != expected_interp:
        mismatches.append(
            f"interpreter sha256: expected {expected_interp}, "
            f"got {report.interpreter_sha256}")

    expected_libs = sbom.get("libraries") or {}
    if expected_libs:
        actual = {lib["path"]: lib.get("sha256", "")
                  for lib in report.libraries}
        for path, digest in sorted(actual.items()):
            if path not in expected_libs:
                mismatches.append(f"library not in SBOM: {path}")
            elif digest and expected_libs[path] and digest != expected_libs[path]:
                mismatches.append(
                    f"library hash mismatch: {path} "
                    f"(sbom={expected_libs[path][:16]}…, actual={digest[:16]}…)")
        for path in sorted(set(expected_libs) - set(actual)):
            mismatches.append(f"SBOM library missing at runtime: {path}")

    expected_merkle = sbom.get("model_weights_merkle_root")
    if expected_merkle and report.model_weights_merkle_root and \
            report.model_weights_merkle_root != expected_merkle:
        mismatches.append(
            f"model weights merkle root mismatch: expected {expected_merkle}, "
            f"got {report.model_weights_merkle_root}")

    report.matches_sbom = not mismatches
    report.sbom_mismatches = mismatches
    return mismatches
