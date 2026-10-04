"""Манифест Bootstrap Sequence (конфигурация Eager Loading / SECCOMP / IPC).

Формат — ``config/bootstrap_manifest.json``; схема валидируется при загрузке.
Манифест определяет:
  * какие модули обязаны быть импортированы ДО применения SECCOMP (F-E-07);
  * warm-up хуки моделей (module:function);
  * профиль и режим SECCOMP (Приложение В);
  * целевой UDS основной шины (F-E-04);
  * ссылку на эталон SBOM для измерения целостности (F-E-06);
  * точку входа основного цикла.
"""
from __future__ import annotations

import importlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


class ManifestError(ValueError):
    """Манифест невалиден."""


@dataclass(frozen=True)
class SeccompConfig:
    profile: str                      # путь к seccomp_profile*.json
    mode: str = "strict"              # strict | extended (dev)

    def validate(self) -> None:
        if self.mode not in ("strict", "extended"):
            raise ManifestError(f"seccomp.mode: {self.mode!r} (strict|extended)")
        if not self.profile:
            raise ManifestError("seccomp.profile: пустой путь")


@dataclass(frozen=True)
class BootstrapManifest:
    eager_required: tuple[str, ...] = ()
    eager_optional: tuple[str, ...] = ()
    warmup_hooks: tuple[str, ...] = ()          # "module.path:function"
    seccomp: SeccompConfig = field(
        default_factory=lambda: SeccompConfig(profile="", mode="strict"))
    rag_socket: str = "/run/zt-core/rag.sock"
    audit_spool: str = ""                        # JSONL-спул событий WORM
    sbom_reference: str = ""                     # config/sbom_reference.json
    main_loop: str = ""                          # "module:function" (опционально)
    interpreter_min_version: tuple[int, int] = (3, 11)
    require_glibc: bool = True                   # F-E-08

    # -- загрузка ----------------------------------------------------------------
    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "BootstrapManifest":
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(f"cannot load manifest {p}: {exc}") from exc
        return cls.from_dict(data, base_dir=p.parent)

    @classmethod
    def from_dict(cls, data: dict[str, Any],
                  base_dir: Path | None = None) -> "BootstrapManifest":
        if not isinstance(data, dict):
            raise ManifestError("manifest root must be an object")
        base = base_dir or Path.cwd()

        def resolve(rel: str) -> str:
            if not rel:
                return ""
            p = Path(rel)
            return str(p if p.is_absolute() else (base / p))

        eager = data.get("eager_loading") or {}
        required = tuple(eager.get("required") or ())
        optional = tuple(eager.get("optional") or ())
        for mod in required + optional:
            if not isinstance(mod, str) or not mod:
                raise ManifestError(f"eager_loading: некорректный модуль {mod!r}")
        warmup = tuple(data.get("warmup_hooks") or ())
        for hook in warmup:
            _validate_dotted_call(hook)

        sec = data.get("seccomp") or {}
        seccomp = SeccompConfig(
            profile=resolve(str(sec.get("profile", ""))),
            mode=str(sec.get("mode", "strict")))
        seccomp.validate()

        min_ver_raw = data.get("interpreter_min_version") or [3, 11]
        try:
            min_ver = (int(min_ver_raw[0]), int(min_ver_raw[1]))
        except (TypeError, ValueError, IndexError) as exc:
            raise ManifestError(f"interpreter_min_version invalid: {exc}") from exc

        return cls(
            eager_required=required,
            eager_optional=optional,
            warmup_hooks=warmup,
            seccomp=seccomp,
            rag_socket=str(data.get("rag_socket", "/run/zt-core/rag.sock")),
            audit_spool=resolve(str(data.get("audit_spool", ""))),
            sbom_reference=resolve(str(data.get("sbom_reference", ""))),
            main_loop=str(data.get("main_loop", "")),
            interpreter_min_version=min_ver,
            require_glibc=bool(data.get("require_glibc", True)),
        )

    # -- импорт хуков --------------------------------------------------------------
    def resolve_callable(self, dotted: str) -> Callable[[], Any]:
        """'pkg.mod:function' -> вызываемый объект (с информативными ошибками)."""
        module_name, func_name = _validate_dotted_call(dotted)
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise ManifestError(
                f"cannot import module {module_name!r} for hook {dotted!r}: {exc}"
            ) from exc
        func = getattr(module, func_name, None)
        if func is None or not callable(func):
            raise ManifestError(
                f"{module_name!r} has no callable {func_name!r} (hook {dotted!r})")
        return func


def _validate_dotted_call(dotted: str) -> tuple[str, str]:
    if not isinstance(dotted, str) or ":" not in dotted:
        raise ManifestError(
            f"hook обязан иметь формат 'module.path:function': {dotted!r}")
    module_name, _, func_name = dotted.partition(":")
    if not module_name or not func_name:
        raise ManifestError(f"hook: пустое имя модуля/функции: {dotted!r}")
    return module_name, func_name
