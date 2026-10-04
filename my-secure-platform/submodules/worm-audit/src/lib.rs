//! ZT-AI-CORE WORM-аудит (L7) — неизменяемый журнал с криптографической
//! защитой от truncation (ТЗ v2.4, Раздел 3.5, docs/07-worm-audit.md).
//!
//! * [`record`]     — запись, BLAKE3 hash-chain (F-G-01/02, Приложение Б п.3);
//! * [`chain`]      — append-only писатель, anti-replay nonce+TTL (F-G-03),
//!                      sync-политики (NF-03), верификация;
//! * [`checkpoint`] — чекпоинты: ≥1000 записей ИЛИ ≥60 с, Ed25519-подпись;
//! * [`anchors`]    — dual-anchor: TPM NV-Counter (≤1/час, износ) + внешний
//!                      WORM (S3 Object Lock), локальный буфер (F-G-04/05);
//! * [`reconcile`]  — сверка при старте, TRUNCATION → RECOVERY + блокировка
//!                      записи (AC-03);
//! * [`service`]    — сборка: цепочка + планировщик чекпоинтов + якоря;
//! * [`server`]     — UDS-сервер контракта audit.proto.

pub mod anchors;
pub mod chain;
pub mod checkpoint;
pub mod record;
pub mod reconcile;
pub mod server;
pub mod service;

pub use anchors::{
    AnchorError, AnchorStatus, DirectoryAnchor, ExtAvailabilityTracker, ExternalAnchor,
    FailingAnchor, LocalCheckpointBuffer, TpmAnchor,
};
pub use chain::{
    ChainConfig, ChainError, ChainIter, ChainSigner, ChainStats, ChainWriter, SeedSigner,
    SyncPolicy, VerifyReport,
};
pub use checkpoint::{Checkpoint, CheckpointPolicy, CheckpointScheduler};
pub use record::{AuditRecord, RecordKind};
pub use reconcile::{reconcile, ReconcileInput, ReconcileReport, ReconcileVerdict};
pub use service::{AuditService, PublishOutcome, ServiceConfig};

/// Версия спецификации.
pub const SPEC_VERSION: &str = "2.4";
