"""End-to-end тесты Bootstrap Sequence (запуск bootstrap.py субпроцессом)."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

BOOTSTRAP = Path(__file__).resolve().parent.parent / "bootstrap.py"
MANIFEST = Path(__file__).resolve().parent.parent / "config" / "bootstrap_manifest.json"
SANDBOX_ROOT = Path(__file__).resolve().parent.parent


def _env(**extra) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = (f"{SANDBOX_ROOT}{os.pathsep}{SANDBOX_ROOT / 'seccomp'}"
                         + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""))
    env["ZT_IN_BWRAP"] = "1"          # эмуляция запуска из run.sh
    env.update({k: str(v) for k, v in extra.items()})
    return env


def _run_bootstrap(args: list[str], term_after: float | None = None,
                   timeout: float = 30.0) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(
        [sys.executable, str(BOOTSTRAP), "--manifest", str(MANIFEST), *args],
        env=_env(), stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    if term_after is not None:
        time.sleep(term_after)
        proc.send_signal(signal.SIGTERM)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def test_print_plan():
    res = _run_bootstrap(["--print-plan"])
    assert res.returncode == 0
    plan = json.loads(res.stdout)
    stages = [p["stage"] for p in plan]
    assert stages[0].startswith("BWRAP_LAUNCH")
    assert any("SECCOMP" in s for s in stages)


def test_self_test_offline():
    res = _run_bootstrap(["--self-test"])
    assert "SELF-TEST PASSED" in res.stdout, res.stdout + res.stderr
    assert res.returncode == 0


def test_dev_run_skip_seccomp_full_cycle(tmp_path: Path):
    spool = tmp_path / "spool.jsonl"
    res = _run_bootstrap(["--dev-mode", "--skip-seccomp",
                          "--audit-spool", str(spool)], term_after=1.5)
    assert res.returncode == 0, res.stderr
    for stage in ("BWRAP_LAUNCH", "EXEC_INTERPRETER", "EAGER_LOADING",
                  "CAPABILITY_DROP", "SECCOMP_ARMED", "MAPS_VERIFY",
                  "INTEGRITY", "RUNNING"):
        assert stage in res.stderr, f"нет этапа {stage}:\n{res.stderr}"
    events = [json.loads(l) for l in spool.read_text().splitlines() if l.strip()]
    kinds = {e["payload"].get("stage") for e in events
             if e["kind"] == "RECORD_KIND_BOOTSTRAP"}
    assert {"START", "RUNNING"} <= kinds
    integrity_events = [e for e in events if e["kind"] == "RECORD_KIND_INTEGRITY"]
    assert integrity_events, "IntegrityReport не записан в WORM-спул"
    rep = integrity_events[0]["payload"]
    assert len(rep["interpreter_sha256"]) == 64


def test_dev_run_extended_seccomp_survives(tmp_path: Path):
    """Процесс живёт с применённым расширенным профилем (dev-контур)."""
    spool = tmp_path / "spool.jsonl"
    ext = SANDBOX_ROOT / "bwrap" / "seccomp_profile_extended.json"
    res = _run_bootstrap(["--dev-mode", "--seccomp-profile", str(ext),
                          "--audit-spool", str(spool)], term_after=1.5)
    assert res.returncode == 0, res.stderr
    assert "EXTENDED" in res.stderr
    assert "RUNNING" in res.stderr


def test_dev_run_strict_seccomp_full_cycle(tmp_path: Path):
    """STRICT-профиль Приложения В: полный цикл без SIGSYS (AC-01/09/10 в dev)."""
    spool = tmp_path / "spool.jsonl"
    strict = SANDBOX_ROOT / "bwrap" / "seccomp_profile.json"
    res = _run_bootstrap(["--dev-mode", "--seccomp-profile", str(strict),
                          "--audit-spool", str(spool)], term_after=2.0)
    assert res.returncode == 0, f"строго-профильный прогон погиб:\n{res.stderr}"
    assert "STRICT" in res.stderr
    assert "MAPS_VERIFY" in res.stderr and "RUNNING" in res.stderr
    assert res.returncode != -signal.SIGSYS


def test_strict_without_dev_mode_requires_bwrap_env(tmp_path: Path):
    """Без ZT_IN_BWRAP и без dev-режима Шаг 1 обязан завершить процесс (F-E-01)."""
    env = _env()
    env.pop("ZT_IN_BWRAP", None)
    # ppid != 1 гарантирован в тестовом окружении
    proc = subprocess.run(
        [sys.executable, str(BOOTSTRAP), "--manifest", str(MANIFEST),
         "--skip-seccomp"],
        env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 3, proc.stderr
    assert "bwrap" in proc.stderr


def test_non_dev_mode_fatal_on_missing_warmup(tmp_path: Path):
    """Без dev-режима недоступный warm-up hook фатален (F-E-07, exit 3)."""
    res = _run_bootstrap(["--skip-seccomp"], term_after=None, timeout=30)
    assert res.returncode == 3, res.stderr
    assert "BOOTSTRAP FAILED" in res.stderr or "warm-up" in res.stderr


def test_skip_seccomp_rejected_outside_dev_unit():
    """Шаг 5: --skip-seccomp вне dev-режима — конфигурационная ошибка."""
    sys.path.insert(0, str(SANDBOX_ROOT))
    import bootstrap as bs
    from ztbootstrap.manifest import BootstrapManifest

    manifest = BootstrapManifest.load(MANIFEST)
    runner = bs.BootstrapRunner(manifest, dev_mode=False, skip_seccomp=True)
    with pytest.raises(bs.BootstrapError) as exc_info:
        runner.step5_seccomp_arm()
    assert exc_info.value.exit_code == bs.EXIT_CONFIG_ERROR
    assert "--skip-seccomp" in str(exc_info.value)


def test_capability_drop_verified_in_dev(tmp_path: Path):
    """После capset(2)+PR_CAPBSET_DROP проверка F-E-09 проходит (AC-10)."""
    spool = tmp_path / "spool.jsonl"
    res = _run_bootstrap(["--dev-mode", "--skip-seccomp",
                          "--audit-spool", str(spool)], term_after=1.5)
    assert res.returncode == 0
    events = [json.loads(l) for l in spool.read_text().splitlines() if l.strip()]
    capdrop = [e for e in events
               if e["payload"].get("stage") == "CAPABILITY_DROP"]
    assert capdrop
    detail = capdrop[0]["payload"]["detail"]
    assert "CapEff=0x0000000000000000" in detail
    assert "NoNewPrivs=1" in detail
