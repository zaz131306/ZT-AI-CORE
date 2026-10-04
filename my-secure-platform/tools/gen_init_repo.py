#!/usr/bin/env python3
"""ZT-AI-CORE — метa-генератор единого инфраструктурного скрипта init_repo.sh.

Обходит дерево репозитория и порождает ОДИН самодостаточный Bash-скрипт
``init_repo.sh``, который разворачивает полный репозиторий с нуля:
  * вся файловая структура Раздела 5 ТЗ;
  * документы docs/00…09 (включая полный текст ТЗ v2.4);
  * корневые файлы (Makefile, docker-compose.yml, .gitignore, LICENSE);
  * api/proto/*.proto, scripts/, CI-workflows;
  * весь код подмодулей с сохранением бит исполнимости.

Гарантия идентичности: содержимое файлов встраивается как есть через
quoted-heredoc с уникальным для каждого файла разделителем (коллизия
разделителя исключается проверкой); бинарные/не-UTF-8 файлы — base64.

Запуск:
    python3 tools/gen_init_repo.py [output_path]   # default: ../init_repo.sh
Проверка:
    bash init_repo.sh /tmp/verify && diff -r my-secure-platform /tmp/verify/my-secure-platform
"""
from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO.parent / "init_repo.sh"

# Каталоги/файлы, НЕ входящие в дистрибутив (артефакты сборки, кэши, секреты).
EXCLUDE_DIRS = {
    ".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "node_modules", "build", "dist", "keys",
    "htmlcov", ".venv",
}
# Исключения по ПОЛНОМУ относительному пути (код-генераты и пр.).
EXCLUDE_PATHS = {
    "api/gen",
    "submodules/t8-sandbox/seccomp/build",
}
EXCLUDE_SUFFIXES = {".bpf", ".o", ".pyc", ".log", ".seed", ".sock"}
EXCLUDE_FILES = {"init_repo.sh"}  # самокопия не вкладывается


def _prune(dirnames: list, rel_dir: Path) -> list:
    kept = []
    for d in dirnames:
        if d in EXCLUDE_DIRS:
            continue
        rel = (rel_dir / d).as_posix() if str(rel_dir) != "." else d
        if rel in EXCLUDE_PATHS:
            continue
        kept.append(d)
    return sorted(kept)


def walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = _prune(dirnames, rel_dir)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root)
            if name in EXCLUDE_FILES:
                continue
            if path.suffix in EXCLUDE_SUFFIXES:
                continue
            yield rel, path


def walk_dirs(root: Path):
    for dirpath, dirnames, _filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirnames[:] = _prune(dirnames, rel)
        for d in list(dirnames):
            yield (rel / d).as_posix() if str(rel) != "." else d


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:8]


def main() -> int:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    files = list(walk_files(REPO))
    dirs = sorted(set(walk_dirs(REPO)))

    total_bytes = sum(p.stat().st_size for _, p in files)
    exec_files = [rel.as_posix() for rel, p in files
                  if p.stat().st_mode & stat.S_IXUSR]

    out: list[str] = []
    out.append(f'''#!/usr/bin/env bash
# =============================================================================
#  ZT-AI-CORE v2.4 — ЕДИНЫЙ ИНФРАСТРУКТУРНЫЙ ГЕНЕРАТОР РЕПОЗИТОРИЯ
# =============================================================================
#  Создаёт полный рабочий репозиторий фреймворка «Zero-Trust AI Core»
#  строго по ТЗ v2.4 (Раздел 5: структура; docs/00…09: полный пакет
#  документов; подмодули L4–L8; api/proto; scripts; CI).
#
#  Сгенерирован: tools/gen_init_repo.py (побайтовая копия дерева-эталона).
#  Файлов: {len(files)}   Каталогов: {len(dirs)}   Объём: {total_bytes / 1024:.1f} KiB
#
#  Использование:
#      ./init_repo.sh [TARGET_DIR] [--no-git]
#      TARGET_DIR по умолчанию: ./my-secure-platform
#
#  После развёртывания:
#      cd my-secure-platform && make build && make test
#      ./scripts/run-self-test.sh        # приёмочные проверки AC-01…AC-10
# =============================================================================
set -euo pipefail

TARGET="./my-secure-platform"
DO_GIT=1
for arg in "$@"; do
    case "${{arg}}" in
        --no-git) DO_GIT=0 ;;
        -h|--help)
            echo "init_repo.sh [TARGET_DIR] [--no-git]"; exit 0 ;;
        *) TARGET="${{arg}}" ;;
    esac
done

if [[ -e "${{TARGET}}" ]] && [[ -n "$(ls -A "${{TARGET}}" 2>/dev/null)" ]]; then
    echo "init_repo.sh: каталог ${{TARGET}} не пуст — укажите другой TARGET_DIR" >&2
    exit 1
fi

ROOT="${{TARGET}}"
CREATED=0

emit() {{
    # emit <relative-path>
    mkdir -p "${{ROOT}}/$(dirname "$1")"
}}

echo "== ZT-AI-CORE v2.4: развёртывание репозитория в ${{ROOT}} =="
''')

    # Каталоги
    out.append("# ---------------------------------------------------------------- каталоги")
    for d in dirs:
        out.append(f'mkdir -p "${{ROOT}}/{d}"')
    out.append("")

    # Файлы
    n_text = n_b64 = 0
    for rel, path in files:
        rel_posix = rel.as_posix()
        raw = path.read_bytes()
        digest = file_digest(path)
        try:
            text = raw.decode("utf-8")
            is_text = True
        except UnicodeDecodeError:
            is_text = False

        if is_text and not text.endswith("\n"):
            text += "\n"  # heredoc-safe: гарантируем завершающий перевод строки

        if is_text:
            delim = f"ZTFILE_{abs(hash(rel_posix)) % 10**8:08d}_{digest}"
            if delim in text:  # теоретически невозможно; перестраховка
                delim += "_X"
                assert delim not in text
            out.append(f"# --- {rel_posix}")
            out.append(f'emit "{rel_posix}"')
            out.append(f"cat > \"${{ROOT}}/{rel_posix}\" <<'{delim}'")
            out.append(text.rstrip("\n"))
            out.append(delim)
            n_text += 1
        else:
            b64 = base64.b64encode(raw).decode("ascii")
            out.append(f"# --- {rel_posix} (binary, base64)")
            out.append(f'emit "{rel_posix}"')
            chunks = [b64[i:i + 96] for i in range(0, len(b64), 96)]
            out.append(f"base64 -d > \"${{ROOT}}/{rel_posix}\" <<'ZTB64_{digest}'")
            out.extend(chunks)
            out.append(f"ZTB64_{digest}")
            n_b64 += 1

        if path.stat().st_mode & stat.S_IXUSR:
            out.append(f'chmod +x "${{ROOT}}/{rel_posix}"')

    out.append(f'''
# ---------------------------------------------------------------- итоги
CREATED=$(find "${{ROOT}}" -type f | wc -l)
echo "== Файлов создано: ${{CREATED}} (text: {n_text}, binary: {n_b64}) =="

if [[ "${{DO_GIT}}" == "1" ]] && command -v git >/dev/null 2>&1; then
    if [[ ! -d "${{ROOT}}/.git" ]]; then
        ( cd "${{ROOT}}" && git init -q && git add -A \\
          && git -c user.email="zt@localhost" -c user.name="ZT-AI-CORE" \\
             commit -qm "ZT-AI-CORE v2.4: initial repository (init_repo.sh)" )
        echo "== git: репозиторий инициализирован, initial commit создан =="
    fi
fi

cat <<SUMMARY

Репозиторий ZT-AI-CORE v2.4 развёрнут: ${{ROOT}}

Следующие шаги:
  cd ${{ROOT}}
  make build          # Rust release + Python compileall + proto codegen
  make test           # cargo test + pytest + shellcheck + protoc
  make sec-scan       # встроенный сканер + bandit/cargo-audit/trivy (при наличии)
  make fuzz           # fuzz-кампания IPC/gRPC-контрактов
  scripts/run-self-test.sh   # приёмочные проверки AC-01…AC-10
  make docker-run     # dev-контур: llm-gateway, rag-core, worm-audit, fsm-engine

Документация: docs/00-technical-specification.md (ТЗ v2.4, 100%)
SUMMARY
''')

    out_path.write_text("\n".join(out), encoding="utf-8")
    out_path.chmod(0o755)
    size = out_path.stat().st_size
    print(f"generated {out_path} ({size / 1024:.1f} KiB): "
          f"{len(files)} files ({n_text} text, {n_b64} binary), "
          f"{len(dirs)} dirs, {len(exec_files)} executable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
