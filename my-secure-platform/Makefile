# ============================================================================
# ZT-AI-CORE v2.4 — корневой Makefile
# Цели ТЗ: build | test | fuzz | sec-scan | docker-run | clean
# ============================================================================
SHELL := /bin/bash
.DEFAULT_GOAL := help

# rustup ставит тулчейн в ~/.cargo/bin — подмешиваем в PATH
export PATH := $(HOME)/.cargo/bin:$(PATH)

ROOT            := $(CURDIR)
SUBMODULES      := $(ROOT)/submodules
RUST_CRATES     := hal-common fsm-engine worm-audit
PYTHON_MODULES  := llm-gateway rag-core t8-sandbox
PROTO_DIR       := $(ROOT)/api/proto
PROTO_GEN       := $(ROOT)/api/gen
BUILD_DIR       := $(ROOT)/build
CARGO_FLAGS     := --release

PYTHON   ?= python3
PYTEST   ?= $(PYTHON) -m pytest
CARGO    ?= cargo
PROTOC   ?= $(PYTHON) -m grpc_tools.protoc

# ----------------------------------------------------------------------------
.PHONY: help
help: ## Показать справку по целям
	@echo "ZT-AI-CORE v2.4 — доступные цели:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ----------------------------------------------------------------------------
.PHONY: build
build: build-rust build-python proto ## Собрать все подмодули (Rust release + Python compileall + proto codegen)

.PHONY: build-rust
build-rust: ## cargo build --release для всех Rust-крейтов
	@for crate in $(RUST_CRATES); do \
	  echo "==> cargo build $(CARGO_FLAGS): $$crate"; \
	  (cd $(SUBMODULES)/$$crate && $(CARGO) build $(CARGO_FLAGS)) || exit 1; \
	done

.PHONY: build-python
build-python: ## Байт-компиляция Python-модулей (проверка синтаксиса)
	@$(PYTHON) -m compileall -q $(SUBMODULES)/llm-gateway $(SUBMODULES)/rag-core $(SUBMODULES)/t8-sandbox
	@echo "==> Python modules OK"

.PHONY: proto
proto: ## Валидация .proto и codegen (Python gRPC stubs) в api/gen/
	@mkdir -p $(PROTO_GEN)/python $(BUILD_DIR)
	@$(PROTOC) --proto_path=$(PROTO_DIR) \
	  --python_out=$(PROTO_GEN)/python --grpc_python_out=$(PROTO_GEN)/python \
	  $(PROTO_DIR)/sandbox.proto $(PROTO_DIR)/fsm.proto $(PROTO_DIR)/audit.proto $(PROTO_DIR)/rag.proto
	@if command -v protoc >/dev/null 2>&1; then \
	  protoc --proto_path=$(PROTO_DIR) -o $(BUILD_DIR)/proto.desc \
	  $(PROTO_DIR)/*.proto && echo "==> protoc descriptor OK"; \
	else \
	  echo "==> protoc (C++) не установлен — descriptor пропущен"; \
	fi
	@echo "==> proto codegen OK -> $(PROTO_GEN)/python"

# ----------------------------------------------------------------------------
.PHONY: test
test: test-rust test-python test-scripts test-proto ## Прогнать все тесты (Rust, Python, shellcheck, proto)

.PHONY: test-rust
test-rust: ## cargo test для всех Rust-крейтов
	@for crate in $(RUST_CRATES); do \
	  echo "==> cargo test: $$crate"; \
	  (cd $(SUBMODULES)/$$crate && $(CARGO) test --quiet) || exit 1; \
	done

.PHONY: test-python
test-python: ## pytest по Python-подмодулям
	@echo "==> pytest: t8-sandbox"; \
	(cd $(SUBMODULES)/t8-sandbox && PYTHONPATH=$(SUBMODULES)/t8-sandbox:$(SUBMODULES)/t8-sandbox/seccomp $(PYTEST) -q tests) || exit 1
	@echo "==> pytest: llm-gateway"; \
	(cd $(SUBMODULES)/llm-gateway && PYTHONPATH=$(SUBMODULES)/llm-gateway $(PYTEST) -q tests) || exit 1
	@echo "==> pytest: rag-core"; \
	(cd $(SUBMODULES)/rag-core && PYTHONPATH=$(SUBMODULES)/rag-core $(PYTEST) -q tests) || exit 1

.PHONY: test-scripts
test-scripts: ## shellcheck для всех .sh
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -x scripts/*.sh \
	    submodules/t8-sandbox/bwrap/run.sh \
	    submodules/t8-sandbox/ebpf/build.sh \
	    submodules/llm-gateway/certs/issue_short_lived.sh && echo "==> shellcheck OK"; \
	else echo "shellcheck не установлен — пропуск"; fi

.PHONY: test-proto
test-proto: proto ## Валидация контрактов gRPC (часть цели test)

# ----------------------------------------------------------------------------
.PHONY: fuzz
fuzz: ## Fuzzing IPC/gRPC-контрактов (этап 7 ТЗ; встроенный детерминированный фаззер)
	@$(PYTHON) tests/fuzz/run_fuzz.py --iterations 5000 --seed 20260101
	@echo "==> fuzz-кампания завершена"

.PHONY: fuzz-heavy
fuzz-heavy: ## Расширенная fuzz-кампания (AFL++/libfuzzer при наличии)
	@if command -v afl-fuzz >/dev/null 2>&1; then \
	  echo "AFL++ обнаружен: используйте harnesses в tests/fuzz/afl/"; \
	else \
	  $(PYTHON) tests/fuzz/run_fuzz.py --iterations 200000 --seed $$RANDOM; \
	fi

# ----------------------------------------------------------------------------
.PHONY: sec-scan
sec-scan: ## Security-сканеры: встроенный + bandit/cargo-audit/trivy/semgrep (при наличии)
	@$(PYTHON) tools/security_scan.py
	@if command -v bandit >/dev/null 2>&1; then bandit -r -q submodules/llm-gateway submodules/rag-core submodules/t8-sandbox -x '*/tests/*' || true; else echo "-- bandit не установлен (pip install bandit)"; fi
	@if command -v cargo-audit >/dev/null 2>&1 || $(CARGO) audit --version >/dev/null 2>&1; then \
	  for crate in $(RUST_CRATES); do (cd $(SUBMODULES)/$$crate && $(CARGO) audit) || true; done; \
	else echo "-- cargo-audit не установлен"; fi
	@if command -v trivy >/dev/null 2>&1; then trivy fs --severity HIGH,CRITICAL . || true; else echo "-- trivy не установлен"; fi
	@if command -v semgrep >/dev/null 2>&1; then semgrep --config=auto --quiet submodules/ || true; else echo "-- semgrep не установлен"; fi
	@echo "==> sec-scan завершён"

.PHONY: seccomp-profile
seccomp-profile: ## Компиляция SECCOMP-профиля JSON -> BPF (scripts/build-sec-profile.sh)
	@./scripts/build-sec-profile.sh

.PHONY: selftest
selftest: ## Приёмочные проверки AC-01…AC-10 (scripts/run-self-test.sh)
	@./scripts/run-self-test.sh

.PHONY: sandbox-demo
sandbox-demo: ## Демонстрационный запуск D8 под bwrap (требует Linux + bwrap + userns)
	@./submodules/t8-sandbox/bwrap/run.sh --mode dev

# ----------------------------------------------------------------------------
.PHONY: docker-run
docker-run: ## Поднять dev-контур: llm-gateway, rag-core, worm-audit, fsm-engine
	@docker compose up --build

.PHONY: docker-down
docker-down: ## Остановить dev-контур
	@docker compose down -v

# ----------------------------------------------------------------------------
.PHONY: clean
clean: ## Очистить артефакты сборки, кэши и временные файлы
	@for crate in $(RUST_CRATES); do \
	  (cd $(SUBMODULES)/$$crate && $(CARGO) clean) 2>/dev/null || true; \
	done
	@find $(ROOT) -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@find $(ROOT) -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -rf $(BUILD_DIR) $(PROTO_GEN) $(ROOT)/.coverage $(ROOT)/htmlcov
	@rm -rf $(SUBMODULES)/t8-sandbox/seccomp/build
	@echo "==> clean OK"

.PHONY: distclean
distclean: clean ## clean + удалить контейнерные тома и локальные данные
	@docker compose down -v --rmi local 2>/dev/null || true
