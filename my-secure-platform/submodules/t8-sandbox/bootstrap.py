#!/usr/bin/env python3
"""ZT-AI-CORE v2.4 — Bootstrap Sequence когнитивного payload D8.

Реализация чек-листа реализации (docs/01-implementation-checklist.md §2)
СТРОГО по шагам:

  Шаг 1. Запуск bwrap с базовой изоляцией — выполняет bwrap/run.sh
         (этот скрипт — цель execve внутри песочницы); здесь выполняется
         контроль, что мы действительно находимся в изолированном контексте.
  Шаг 2. Проверка целевого интерпретатора: python3.11+, glibc (F-E-08).
  Шаг 3. Eager Loading (F-E-07):
           * немедленный import всех C-extensions из манифеста;
           * загрузка весов моделей и warm-up (1 forward pass на dummy-данных);
           * проверка анти-lazy env-флагов;
           * baseline snapshot /proc/self/maps.
  Шаг 4. Capability Drop (F-E-09):
           * prctl(PR_SET_NO_NEW_PRIVS, 1);
           * prctl(PR_CAPBSET_DROP, cap) для каждого cap bounding set;
           * проверка /proc/self/status: CapEff==CapPrm==CapInh==0,
             NoNewPrivs==1; иначе exit(1).
  Шаг 5. SECCOMP: seccomp(SECCOMP_SET_MODE_FILTER) — профиль Приложения В.
  Шаг 6. Post-SECCOMP verify:
           * сверка /proc/self/maps с baseline (расхождение → SIGKILL);
           * IntegrityReport + сверка с SBOM (F-E-06; mismatch → BOOT_FAILSAFE);
           * старт основного цикла RAG / подключение к /run/zt-core/rag.sock.

Коды завершения:
  0 — штатный старт/завершение;
  1 — провал проверки Capability Drop (чек-лист §2 Шаг 4: exit(1));
  2 — BOOT_FAILSAFE (целостность рантайма не подтверждена, F-E-06);
  3 — конфигурационная ошибка (манифест/профиль/окружение).
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import signal
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# --- bootstrap sys.path: пакет ztbootstrap (рядом) и ztseccomp (seccomp/) -----
_HERE = Path(__file__).resolve().parent
for _p in (str(_HERE), str(_HERE / "seccomp")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ztbootstrap.events import (  # noqa: E402
    KIND_BOOTSTRAP,
    KIND_INTEGRITY,
    EventSpool,
)
from ztbootstrap.integrity import (  # noqa: E402
    IntegrityReport,
    collect_runtime_report,
    compare_with_sbom,
)
from ztbootstrap.manifest import BootstrapManifest, ManifestError  # noqa: E402
from ztbootstrap.maps import diff_maps, maps_hash, read_maps  # noqa: E402
from ztseccomp.apply import (  # noqa: E402
    SeccompError,
    clear_capability_sets,
    drop_bounding_capabilities,
    program_blake3,
    read_caps_status,
    set_no_new_privs,
    verify_capability_drop,
    apply_bpf_filter,
)
from ztseccomp.profile import ProfileError, compile_profile  # noqa: E402

EXIT_OK = 0
EXIT_CAPDROP_FAILED = 1
EXIT_BOOT_FAILSAFE = 2
EXIT_CONFIG_ERROR = 3

# Анти-lazy env-флаги F-E-07 (должны быть установлены ещё run.sh до execve;
# здесь — контроль и аварийная доустановка).
REQUIRED_ENV = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "GRPC_DISABLE_DYNAMIC_PLUGINS": "1",
    "TORCH_DISABLE_DYNAMIC_JIT": "1",
}


class BootstrapError(RuntimeError):
    """Ошибка bootstrap-этапа с кодом завершения."""

    def __init__(self, stage: str, message: str, exit_code: int = EXIT_CONFIG_ERROR):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.exit_code = exit_code


@dataclass
class StepResult:
    stage: str
    ok: bool
    detail: str = ""
    duration_ms: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)


def _log(stage: str, msg: str) -> None:
    print(f"[bootstrap][{stage}] {msg}", file=sys.stderr, flush=True)


def force_sigkill(reason: str, spool: EventSpool | None = None) -> None:
    """Шаг 6: «любое расхождение → SIGKILL».

    Сначала событие в WORM-спул, затем SIGKILL себе. Если kill(2) запрещён
    фильтром (строгий профиль Приложения В не содержит kill) — вызов сам
    приведёт к SECCOMP_RET_KILL_PROCESS; финальный fallback — os._exit(137).
    """
    _log("MAPS_VERIFY", f"FATAL: {reason} — принудительный SIGKILL (F-E-07)")
    if spool is not None:
        spool.emit(KIND_BOOTSTRAP, {
            "stage": "MAPS_VERIFY", "ok": False, "fatal": reason,
            "action": "SIGKILL"})
        spool.close()
    try:
        os.kill(os.getpid(), signal.SIGKILL)
    except BaseException:  # noqa: BLE001 - последний рубеж, детали не важны
        pass
    os._exit(137)


class BootstrapRunner:
    """Оркестратор Bootstrap Sequence (порядок шагов фиксирован чек-листом)."""

    def __init__(self, manifest: BootstrapManifest, *,
                 dev_mode: bool = False,
                 skip_seccomp: bool = False,
                 spool_path: str = ""):
        self.manifest = manifest
        self.dev_mode = dev_mode
        self.skip_seccomp = skip_seccomp
        self.spool = EventSpool(path=spool_path or manifest.audit_spool)
        self.results: list[StepResult] = []
        self._maps_baseline: str = ""
        self._maps_baseline_hash: str = ""
        self._seccomp_program_hash: str = ""
        self._sbom_data: dict[str, Any] | None = None
        self._sbom_load_error: str = ""

    # ------------------------------------------------------------------ utils
    def _record(self, stage: str, ok: bool, detail: str = "",
                started: float = 0.0, **data: Any) -> StepResult:
        res = StepResult(stage=stage, ok=ok, detail=detail,
                         duration_ms=(time.monotonic() - started) * 1000
                         if started else 0.0,
                         data=data)
        self.results.append(res)
        self.spool.emit(KIND_BOOTSTRAP, {
            "stage": stage, "ok": ok, "detail": detail[:512],
            "duration_ms": round(res.duration_ms, 3), **data})
        _log(stage, f"{'OK' if ok else 'FAIL'}: {detail}")
        return res

    def _fail(self, stage: str, message: str,
              exit_code: int = EXIT_CONFIG_ERROR) -> None:
        self._record(stage, False, message)
        raise BootstrapError(stage, message, exit_code)

    # -------------------------------------------------------------- Шаг 1
    def step1_verify_sandbox_context(self) -> StepResult:
        """Контроль, что процесс запущен внутри bwrap-контекста (Шаг 1)."""
        t0 = time.monotonic()
        stage = "BWRAP_LAUNCH"
        in_bwrap_env = os.environ.get("ZT_IN_BWRAP") == "1"
        pid_ns_isolated = os.getppid() == 1
        inside = in_bwrap_env or pid_ns_isolated
        detail = (f"ZT_IN_BWRAP={int(in_bwrap_env)} ppid={os.getppid()} "
                  f"pid_ns_isolated={int(pid_ns_isolated)}")
        if inside:
            return self._record(stage, True, detail, t0)
        if self.dev_mode:
            return self._record(
                stage, True,
                f"DEV: вне bwrap-контекста ({detail}) — запуск разрешён "
                f"только в dev-режиме", t0, dev_outside_sandbox=True)
        self._fail(stage,
                   "процесс не внутри bwrap (нет ZT_IN_BWRAP=1 и ppid != 1); "
                   "в prod запуск только через bwrap/run.sh (F-E-01)",
                   EXIT_CONFIG_ERROR)
        raise AssertionError("unreachable")

    # -------------------------------------------------------------- Шаг 2
    def step2_verify_interpreter(self) -> StepResult:
        """Целевой интерпретатор: python >= 3.11, glibc (F-E-08)."""
        t0 = time.monotonic()
        stage = "EXEC_INTERPRETER"
        ver = sys.version_info
        min_ver = self.manifest.interpreter_min_version
        if (ver.major, ver.minor) < min_ver:
            self._fail(stage,
                       f"python {ver.major}.{ver.minor} < требуемого "
                       f"{min_ver[0]}.{min_ver[1]}", EXIT_CONFIG_ERROR)
        libc_name, libc_ver = platform.libc_ver()
        is_glibc = libc_name.lower() in ("glibc", "gnu c library")
        if self.manifest.require_glibc and not is_glibc:
            if self.dev_mode:
                self._record(stage, True,
                             f"DEV: libc={libc_name!r} (glibc не подтверждён) — "
                             "F-E-08 требует glibc (musl использует clone3)",
                             t0, libc=libc_name, dev_relaxed=True)
            else:
                self._fail(stage,
                           f"libc={libc_name!r}: F-E-08 требует glibc "
                           "(musl мигрирует на запрещённый clone3)",
                           EXIT_CONFIG_ERROR)
        return self._record(
            stage, True,
            f"python {ver.major}.{ver.minor}.{ver.micro} libc={libc_name} "
            f"{libc_ver} exe={sys.executable}", t0,
            libc=libc_name, libc_version=libc_ver)

    # -------------------------------------------------------------- Шаг 3
    def step3_eager_loading(self) -> StepResult:
        """Eager Loading + Warm-up + baseline maps (F-E-07)."""
        t0 = time.monotonic()
        stage = "EAGER_LOADING"

        # 3a. Анти-lazy env-флаги.
        for name, want in REQUIRED_ENV.items():
            got = os.environ.get(name)
            if got != want:
                os.environ[name] = want
                _log(stage, f"WARN: {name}={got!r} != {want!r} — установлено "
                            f"принудительно (должно задаваться до execve в run.sh)")

        # 3b. Немедленный import всех C-extensions (без lazy loading).
        imported: list[str] = []
        failed_required: list[str] = []
        for mod in self.manifest.eager_required:
            try:
                importlib.import_module(mod)
                imported.append(mod)
            except ImportError as exc:
                failed_required.append(f"{mod}: {exc}")
        imported_optional: list[str] = []
        for mod in self.manifest.eager_optional:
            try:
                importlib.import_module(mod)
                imported_optional.append(mod)
            except ImportError:
                _log(stage, f"optional module unavailable: {mod}")

        if failed_required:
            if self.dev_mode:
                _log(stage, "DEV: required modules missing: "
                            + "; ".join(failed_required))
            else:
                self._fail(
                    stage,
                    "Eager Loading провален (F-E-07): не импортированы "
                    "обязательные модули: " + "; ".join(failed_required),
                    EXIT_CONFIG_ERROR)

        # 3c. Warm-up: 1 forward pass на dummy-данных для каждой модели.
        warmups: list[str] = []
        for hook in self.manifest.warmup_hooks:
            try:
                fn: Callable[[], Any] = self.manifest.resolve_callable(hook)
                fn()
                warmups.append(hook)
            except ManifestError as exc:
                if self.dev_mode:
                    _log(stage, f"DEV: warm-up hook недоступен: {exc}")
                else:
                    self._fail(stage,
                               f"warm-up обязателен (F-E-07): {exc}",
                               EXIT_CONFIG_ERROR)
            except Exception as exc:  # noqa: BLE001 - warm-up любая ошибка фатальна
                self._fail(stage, f"warm-up hook {hook!r} failed: {exc}",
                           EXIT_CONFIG_ERROR)

        # 3d. Baseline snapshot /proc/self/maps.
        try:
            self._maps_baseline = read_maps()
        except OSError as exc:
            self._fail(stage, f"/proc/self/maps недоступен: {exc}",
                       EXIT_CONFIG_ERROR)
        self._maps_baseline_hash = maps_hash(self._maps_baseline)

        # 3e. Пре-загрузка эталона SBOM В ПАМЯТЬ (F-E-06). После применения
        # SECCOMP (Шаг 5) строгий профиль Приложения В не разрешает statx/
        # faccessat — поэтому всё файловое чтение для Шага 6 выполняется здесь,
        # ДО arming (openat/read whitelist'ом разрешены и после, но существование
        # файла проверяется открытием, а не stat — см. _read_sbom_reference).
        self._sbom_data, self._sbom_load_error = self._read_sbom_reference()

        return self._record(
            stage, True,
            f"imported={len(imported)}+{len(imported_optional)}opt "
            f"warmups={len(warmups)} maps_baseline={self._maps_baseline_hash[:16]}…",
            t0, imported=imported, imported_optional=imported_optional,
            warmups=warmups, failed_required=failed_required,
            maps_baseline_hash=self._maps_baseline_hash)

    def _read_sbom_reference(self) -> tuple[dict[str, Any] | None, str]:
        """Чтение эталона SBOM через open() (без stat) — безопасно до и после arming."""
        path = self.manifest.sbom_reference
        if not path:
            return None, ""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return None, f"{path}: root is not an object"
            return data, ""
        except FileNotFoundError:
            return None, ""
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"{path}: {exc}"

    # -------------------------------------------------------------- Шаг 4
    def step4_capability_drop(self) -> StepResult:
        """Capability Drop (F-E-09): NO_NEW_PRIVS + PR_CAPBSET_DROP + verify."""
        t0 = time.monotonic()
        stage = "CAPABILITY_DROP"
        before = read_caps_status()
        try:
            set_no_new_privs()
        except SeccompError as exc:
            if self.dev_mode and before.no_new_privs == 1:
                _log(stage, f"DEV: NO_NEW_PRIVS уже установлен: {exc}")
            else:
                self._fail(stage, f"PR_SET_NO_NEW_PRIVS failed: {exc}",
                           EXIT_CAPDROP_FAILED)
        try:
            dropped = drop_bounding_capabilities()
        except SeccompError as exc:
            if not self.dev_mode:
                self._fail(stage, f"PR_CAPBSET_DROP failed: {exc}",
                           EXIT_CAPDROP_FAILED)
            _log(stage, f"DEV: capdrop частично недоступен: {exc}")
            dropped = []
        # В bwrap-контексте CapEff уже 0; вне песочницы (dev/CI) обнуляем
        # effective/permitted/inheritable через capset(2), чтобы проверка
        # F-E-09 была честной (AC-10).
        capset_ok = clear_capability_sets()
        try:
            status = verify_capability_drop()
        except SeccompError as exc:
            # Чек-лист §2 Шаг 4: «если хотя бы одно условие не выполнено → exit(1)»
            if self.dev_mode:
                after = read_caps_status()
                return self._record(
                    stage, True,
                    f"DEV: проверка не пройдена ({exc}); CapEff="
                    f"{after.cap_eff:#018x} NoNewPrivs={after.no_new_privs}",
                    t0, dropped_caps=dropped, dev_relaxed=True)
            self._fail(stage, str(exc), EXIT_CAPDROP_FAILED)
        return self._record(
            stage, True,
            f"dropped={len(dropped)} caps; capset_clear={int(capset_ok)}; "
            f"CapEff={status.cap_eff:#018x} "
            f"CapPrm={status.cap_prm:#018x} CapInh={status.cap_inh:#018x} "
            f"NoNewPrivs={status.no_new_privs}",
            t0, dropped_caps=dropped, capset_cleared=capset_ok)

    # -------------------------------------------------------------- Шаг 5
    def step5_seccomp_arm(self) -> StepResult:
        """Применение SECCOMP-фильтра (Приложение В) через SECCOMP_SET_MODE_FILTER."""
        t0 = time.monotonic()
        stage = "SECCOMP_ARMED"
        if self.skip_seccomp:
            if not self.dev_mode:
                self._fail(stage, "--skip-seccomp допустим только в dev-режиме",
                           EXIT_CONFIG_ERROR)
            return self._record(stage, True,
                                "DEV: SECCOMP пропущен (--skip-seccomp)", t0,
                                armed=False, dev_relaxed=True)
        profile_path = self.manifest.seccomp.profile
        if not Path(profile_path).exists():
            self._fail(stage, f"профиль не найден: {profile_path}",
                       EXIT_CONFIG_ERROR)
        try:
            program, report = compile_profile(
                profile_path, arch=platform.machine().lower().replace("amd64", "x86_64"))
        except ProfileError as exc:
            self._fail(stage, f"компиляция профиля провалена: {exc}",
                       EXIT_CONFIG_ERROR)
        self._seccomp_program_hash = program_blake3(program)
        try:
            n_insns = apply_bpf_filter(program)
        except SeccompError as exc:
            # После Шага 4 фильтр обязаны поставить; ошибка фатальна даже в dev.
            self._fail(stage, f"SECCOMP_SET_MODE_FILTER failed: {exc}",
                       EXIT_CAPDROP_FAILED)
        mode = "STRICT (Приложение В)" if self.manifest.seccomp.mode == "strict" \
            else "EXTENDED (dev)"
        # После arming строгий профиль не разрешает fsync — спул событий
        # переходит в режим write+flush (доставка в WORM — через UDS-шину).
        if self.manifest.seccomp.mode == "strict":
            self.spool.sync = False
        return self._record(
            stage, True,
            f"фильтр применён: {mode}, {n_insns} инструкций, "
            f"insns_total={report.instruction_count}, "
            f"blake3={self._seccomp_program_hash[:16]}…",
            t0, armed=True, mode=self.manifest.seccomp.mode,
            program_blake3=self._seccomp_program_hash,
            skipped_names=report.skipped_names)

    # -------------------------------------------------------------- Шаг 6
    def step6_post_verify(self) -> StepResult:
        """Сверка maps с baseline (SIGKILL при дрейфе) + IntegrityReport (F-E-06)."""
        t0 = time.monotonic()
        stage = "MAPS_VERIFY"
        current = read_maps()
        diff = diff_maps(self._maps_baseline, current)
        if not diff.clean:
            reason = (f"maps drift: added={sorted(diff.added_paths)[:5]} "
                      f"removed={sorted(diff.removed_paths)[:5]} "
                      f"perms_changed={list(diff.perms_changed)[:5]}")
            if self.dev_mode:
                self._record(stage, True, f"DEV: {reason} (SIGKILL отменён)",
                             t0, drift=reason, dev_relaxed=True)
            else:
                force_sigkill(reason, self.spool)  # не возвращает управление
        res = self._record(stage, True,
                           f"maps сверены с baseline, hash="
                           f"{maps_hash(current)[:16]}…", t0)

        # IntegrityReport + SBOM (F-E-06, AC-05).
        stage_i = "INTEGRITY"
        t0 = time.monotonic()
        try:
            report: IntegrityReport = collect_runtime_report(
                maps_text=current, skip_library_hashes=self.dev_mode)
            report.maps_baseline_hash = self._maps_baseline_hash
        except Exception as exc:  # noqa: BLE001
            self._fail(stage_i, f"integrity report failed: {exc}",
                       EXIT_BOOT_FAILSAFE)
        mismatches: list[str] = []
        if self._sbom_load_error and not self.dev_mode:
            mismatches = [f"sbom reference error: {self._sbom_load_error}"]
        if self._sbom_data is not None:
            try:
                mismatches = compare_with_sbom(report, self._sbom_data)
            except Exception as exc:  # noqa: BLE001
                mismatches = [f"sbom compare error: {exc}"]
        if mismatches and not self.dev_mode:
            self.spool.emit(KIND_INTEGRITY, report.to_dict())
            self._fail(stage_i,
                       "целостность рантайма не подтверждена SBOM → "
                       f"BOOT_FAILSAFE: {'; '.join(mismatches[:3])}",
                       EXIT_BOOT_FAILSAFE)
        if self._sbom_data is None:
            report.matches_sbom = self.dev_mode
            if not self.dev_mode:
                _log(stage_i, "WARN: эталон SBOM не задан — сверка пропущена "
                              "(в prod F-E-06 обязателен)")
        self.spool.emit(KIND_INTEGRITY, report.to_dict())
        return self._record(
            stage_i, True,
            f"interpreter={report.interpreter_sha256[:16]}… "
            f"libs={len(report.libraries)} sbom_mismatches={len(mismatches)}",
            t0, mismatches=mismatches)

    # ------------------------------------------------------- основной цикл
    @staticmethod
    def _probe_uds(sock_path: str) -> bool:
        """Проба UDS-шины connect(2) — разрешён whitelist; stat-вызовы не используются."""
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.settimeout(1.0)
                s.connect(sock_path)
                return True
            finally:
                s.close()
        except OSError:
            return False

    def step7_start_main_loop(self) -> int:
        """Старт основного цикла RAG / подключение к /run/zt-core/rag.sock."""
        stage = "RUNNING"
        main_loop = self.manifest.main_loop
        if main_loop:
            try:
                fn = self.manifest.resolve_callable(main_loop)
            except ManifestError as exc:
                self._fail(stage, f"main_loop hook недоступен: {exc}",
                           EXIT_CONFIG_ERROR)
            self._record(stage, True, f"запуск основного цикла: {main_loop}")
            result = fn()
            return EXIT_OK if result in (None, 0) else EXIT_CONFIG_ERROR

        # Dev/автономный режим: проба UDS-шины (connect, а не stat — строгий
        # профиль Приложения В не разрешает statx после arming) + heartbeat
        # до SIGTERM.
        sock_path = self.manifest.rag_socket
        bus_alive = self._probe_uds(sock_path)
        if bus_alive:
            self._record(stage, True,
                         f"rag.sock отвечает: {sock_path} (внешний сервер шины)")
        else:
            self._record(stage, True,
                         f"main_loop не задан; rag.sock недоступен ({sock_path}) "
                         "— heartbeat-ожидание (dev)")
        stop = {"flag": False}

        def _on_term(signum: int, _frame: Any) -> None:
            stop["flag"] = True

        signal.signal(signal.SIGTERM, _on_term)
        signal.signal(signal.SIGINT, _on_term)
        while not stop["flag"]:
            time.sleep(1.0)
        self._record(stage, True, "останов по сигналу")
        return EXIT_OK

    # ------------------------------------------------------------- run()
    def run(self) -> int:
        with self.spool:
            self.spool.emit(KIND_BOOTSTRAP, {
                "stage": "START", "ok": True,
                "detail": f"pid={os.getpid()} dev_mode={self.dev_mode} "
                          f"skip_seccomp={self.skip_seccomp}"})
            self.step1_verify_sandbox_context()
            self.step2_verify_interpreter()
            self.step3_eager_loading()
            self.step4_capability_drop()
            self.step5_seccomp_arm()
            self.step6_post_verify()
            return self.step7_start_main_loop()


def _self_test(manifest_path: str) -> int:
    """Офлайн-самопроверка без arming/capdrop: манифест, профиль, maps, merkle."""
    errors: list[str] = []
    try:
        manifest = BootstrapManifest.load(manifest_path)
        print(f"manifest OK: required={list(manifest.eager_required)} "
              f"mode={manifest.seccomp.mode}")
    except ManifestError as exc:
        errors.append(f"manifest: {exc}")
        manifest = None
    try:
        prof = manifest.seccomp.profile if manifest else ""
        if prof and Path(prof).exists():
            program, report = compile_profile(prof)
            print(f"seccomp profile OK: {report.instruction_count} insns, "
                  f"blake3={program_blake3(program)[:16]}…")
        else:
            errors.append(f"seccomp profile not found: {prof!r}")
    except ProfileError as exc:
        errors.append(f"profile: {exc}")
    try:
        text = read_maps()
        print(f"maps OK: entries={len(text.splitlines())} "
              f"hash={maps_hash(text)[:16]}…")
    except OSError as exc:
        errors.append(f"maps: {exc}")
    from ztbootstrap.integrity import merkle_root
    root = merkle_root([b"a", b"b", b"c"])
    print(f"merkle_root OK: {root[:16]}…")
    caps = read_caps_status()
    print(f"caps read OK: CapEff={caps.cap_eff:#018x} "
          f"NoNewPrivs={caps.no_new_privs}")
    if errors:
        print("SELF-TEST FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    print("SELF-TEST PASSED")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bootstrap.py",
        description="ZT-AI-CORE D8 Bootstrap Sequence (чек-лист §2, F-E-07/09)")
    parser.add_argument("--manifest", default=str(_HERE / "config" / "bootstrap_manifest.json"),
                        help="путь к bootstrap_manifest.json")
    parser.add_argument("--seccomp-profile", default="",
                        help="переопределить путь к seccomp-профилю из манифеста")
    parser.add_argument("--dev-mode", action="store_true",
                        help="смягчить фатальные проверки (только dev-контур)")
    parser.add_argument("--skip-seccomp", action="store_true",
                        help="не применять SECCOMP (только вместе с --dev-mode)")
    parser.add_argument("--audit-spool", default="",
                        help="переопределить путь JSONL-спула WORM-событий")
    parser.add_argument("--self-test", action="store_true",
                        help="офлайн-самопроверка (без capdrop/arming)")
    parser.add_argument("--print-plan", action="store_true",
                        help="напечатать план шагов и выйти")
    args = parser.parse_args(argv)

    if args.print_plan:
        print(json.dumps([
            {"step": 1, "stage": "BWRAP_LAUNCH", "what": "контроль изолированного контекста"},
            {"step": 2, "stage": "EXEC_INTERPRETER", "what": "python3.11+, glibc (F-E-08)"},
            {"step": 3, "stage": "EAGER_LOADING", "what": "import C-extensions, warm-up моделей, baseline /proc/self/maps (F-E-07)"},
            {"step": 4, "stage": "CAPABILITY_DROP", "what": "NO_NEW_PRIVS + PR_CAPBSET_DROP + verify CapEff==0 (F-E-09)"},
            {"step": 5, "stage": "SECCOMP_ARMED", "what": "SECCOMP_SET_MODE_FILTER, профиль Приложения В"},
            {"step": 6, "stage": "MAPS_VERIFY/INTEGRITY", "what": "сверка maps (SIGKILL при дрейфе), IntegrityReport+SBOM (F-E-06)"},
            {"step": 7, "stage": "RUNNING", "what": "основной цикл RAG / rag.sock"},
        ], ensure_ascii=False, indent=2))
        return EXIT_OK

    if args.self_test:
        return _self_test(args.manifest)

    try:
        manifest = BootstrapManifest.load(args.manifest)
    except ManifestError as exc:
        print(f"[bootstrap] FATAL: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    if args.seccomp_profile:
        from ztbootstrap.manifest import SeccompConfig
        mode = "extended" if "extended" in args.seccomp_profile else manifest.seccomp.mode
        manifest = BootstrapManifest(
            **{**manifest.__dict__,
               "seccomp": SeccompConfig(profile=args.seccomp_profile, mode=mode)})

    runner = BootstrapRunner(
        manifest,
        dev_mode=args.dev_mode,
        skip_seccomp=args.skip_seccomp,
        spool_path=args.audit_spool or os.environ.get("ZT_AUDIT_SPOOL", ""))
    try:
        return runner.run()
    except BootstrapError as exc:
        print(f"[bootstrap] BOOTSTRAP FAILED: {exc}", file=sys.stderr, flush=True)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
