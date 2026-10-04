"""Общая конфигурация pytest для t8-sandbox: пути импорта и маркеры."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "seccomp"))


def seccomp_usable() -> bool:
    """Доступен ли seccomp(2) в текущем окружении (ядро/контейнер)."""
    if sys.platform != "linux":
        return False
    try:
        from ztseccomp.apply import is_seccomp_available
        return is_seccomp_available()
    except Exception:
        return False


requires_seccomp = pytest.mark.skipif(
    not seccomp_usable(),
    reason="seccomp(2) недоступен в данном окружении")

requires_fork = pytest.mark.skipif(
    not hasattr(os, "fork"), reason="os.fork недоступен")


@pytest.fixture()
def sandbox_root() -> Path:
    return ROOT


@pytest.fixture()
def strict_profile_path(sandbox_root: Path) -> Path:
    return sandbox_root / "bwrap" / "seccomp_profile.json"


@pytest.fixture()
def extended_profile_path(sandbox_root: Path) -> Path:
    return sandbox_root / "bwrap" / "seccomp_profile_extended.json"
