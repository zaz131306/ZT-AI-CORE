ZT-AI-CORE — Zero-Trust AI Core (v2.4)

Enterprise-фреймворк изолированного когнитивного слоя для безопасного развёртывания ИИ-моделей (RAG-агентов) в аппаратно-программном изолированном контуре с нулевым доверием к когнитивному payload (домен D8).
Параметр 	Значение
Версия спецификации 	2.4 (Final, 100%) — docs/00-technical-specification.md
Стек 	Python 3.11+ (glibc), Rust 1.75+, gRPC/Protobuf, Bubblewrap, SECCOMP (custom BPF), eBPF, TPM 2.0
Платформы 	ARM64, x86_64, Nvidia Jetson (Orin/Xavier)
Нормативная база 	ISO/IEC 27001, ISO/IEC 42001, гражданские профили криптографии
Лицензия 	Apache License 2.0



# 1. Развернуть репозиторий из единого генератора (если начинаете с init_repo.sh):
./init_repo.sh ./my-secure-platform && cd my-secure-platform

# 2. Собрать всё (Rust release + byte-compile Python + валидация proto):
make build

# 3. Прогнать все тесты (cargo test, pytest, shellcheck, protoc):
make test

# 4. Security-сканеры и fuzzing контрактов:
make sec-scan
make fuzz

# 5. Dev-контур в контейнерах (4 сервиса ТЗ):
make docker-run

# 6. Приёмочные проверки AC-01…AC-10 (на Linux-хосте):
scripts/run-self-test.sh

# Запуск D8 в песочнице (требует bwrap, glibc-хост):
submodules/t8-sandbox/bwrap/run.sh
