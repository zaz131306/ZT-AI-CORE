//! ZT-AI-CORE FSM-движок (L6) — детерминированное управление жизненным
//! циклом и режимами системы (ТЗ v2.4, Раздел 3.4, Приложение А).
//!
//! * [`state`]    — Lifecycle × Operating Modes, матрица Приложения А;
//! * [`wal`]      — Write-Ahead Log атомарных переходов (F-F-05, AC-04);
//! * [`rollback`] — Pending Rollback Counter (F-F-03), A/B-слоты (F-I-03),
//!                    anti-downgrade (F-I-02), подпись артефактов (F-I-01);
//! * [`engine`]   — движок: переходы, watchdog (NF-05), SELF_TEST,
//!                    реакция на события WORM (F-G-04), форензика;
//! * [`server`]   — UDS-сервер контракта fsm.proto (line-oriented JSON);
//! * [`audit`]    — клиент WORM-шины (публикация FSM_EVENT).

pub mod audit;
pub mod engine;
pub mod rollback;
pub mod server;
pub mod state;
pub mod wal;

pub use engine::{
    EngineConfig, EngineError, EventListener, FlakyWatchdog, FsmEngine, ImmediateWatchdog,
    StateEvent, StateSnapshot, Watchdog,
};
pub use rollback::{RollbackError, RollbackManager, RollbackStatus, SelfTestVerdict, UpdateSlot};
pub use state::{
    lifecycle_edge_allowed, matrix_allowed, transition_allowed, LifecycleState, OperatingMode,
    TransitionTrigger,
};
pub use wal::{WalError, WalRecord, WalRecordType, WalRecovery, WalWriter};

/// Версия спецификации.
pub const SPEC_VERSION: &str = "2.4";
