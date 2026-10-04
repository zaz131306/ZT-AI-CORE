//! FSM-движок: атомарные переходы (F-F-05), watchdog (NF-05), SELF_TEST,
//! обработка событий WORM (truncation → RECOVERY, anchor down → DEGRADED),
//! форензика (dump-state, WAL-tail).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::rollback::{RollbackManager, RollbackStatus, UpdateSlot};
use crate::state::{
    matrix_allowed, transition_allowed, LifecycleState,
    OperatingMode, TransitionTrigger,
};
use crate::wal::{
    recover as wal_recover, SelfTestItemPayload, SelfTestPayload, TransitionPayload, WalError,
    WalRecordType, WalRecovery, WalWriter,
};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("wal error: {0}")]
    Wal(#[from] WalError),
    #[error("matrix violation: {from_lifecycle}×{from_mode} -> {to_lifecycle}×{to_mode}")]
    MatrixViolation {
        from_lifecycle: LifecycleState,
        from_mode: OperatingMode,
        to_lifecycle: LifecycleState,
        to_mode: OperatingMode,
    },
    #[error("lifecycle edge not allowed: {0} -> {1}")]
    EdgeViolation(LifecycleState, LifecycleState),
    #[error("rollback error: {0}")]
    Rollback(#[from] crate::rollback::RollbackError),
    #[error("engine in write-locked state (WORM truncation): переход невозможен до RECOVERY")]
    WriteLocked,
    #[error("shutdown is terminal")]
    TerminalState,
}

/// Событие перехода (fsm.proto:StateEvent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvent {
    pub previous: StateSnapshot,
    pub current: StateSnapshot,
    pub trigger: TransitionTrigger,
    pub reason: String,
    pub timestamp_unix_ns: i64,
    pub duration_ms: u64,
}

/// Снимок состояния (fsm.proto:FsmStateSnapshot).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateSnapshot {
    pub lifecycle: LifecycleState,
    pub mode: OperatingMode,
    pub epoch: u64,
    pub wal_sequence: u64,
    pub timestamp_unix_ns: i64,
    pub reason: String,
    pub last_trigger: TransitionTrigger,
    pub write_locked: bool,
}

/// Watchdog: подтверждение перехода (F-F-05: переход завершён только после
/// записи в WAL + подтверждения watchdog; NF-05: ≤ 500 мс).
pub trait Watchdog: Send {
    fn ack(&mut self, epoch: u64, deadline: Duration) -> bool;
}

/// Dev/CI-watchdog: подтверждает мгновенно.
#[derive(Debug, Default)]
pub struct ImmediateWatchdog;

impl Watchdog for ImmediateWatchdog {
    fn ack(&mut self, _epoch: u64, _deadline: Duration) -> bool {
        true
    }
}

/// Watchdog, который «зависает» после N подтверждений (chaos-тесты, NF-05).
#[derive(Debug)]
pub struct FlakyWatchdog {
    pub acks_left: u32,
}

impl Watchdog for FlakyWatchdog {
    fn ack(&mut self, _epoch: u64, _deadline: Duration) -> bool {
        if self.acks_left == 0 {
            return false;
        }
        self.acks_left -= 1;
        true
    }
}

/// Конфигурация движка.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Таймаут подтверждения watchdog (NF-05: ≤ 500 мс).
    pub watchdog_timeout: Duration,
    /// fsync каждой записи WAL (F-F-05: гарантированный fsync).
    pub wal_fsync: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            watchdog_timeout: Duration::from_millis(500),
            wal_fsync: true,
        }
    }
}

/// Слушатель событий (используется сервером для стрима и WORM-интеграции).
pub type EventListener = Box<dyn FnMut(&StateEvent) + Send>;

/// Детерминированный FSM-движок ZT-AI-CORE (L6).
pub struct FsmEngine {
    lifecycle: LifecycleState,
    mode: OperatingMode,
    epoch: u64,
    reason: String,
    last_trigger: TransitionTrigger,
    write_locked: bool,
    wal: WalWriter,
    recovery_info: WalRecovery,
    rollback: RollbackManager,
    config: EngineConfig,
    watchdog: Box<dyn Watchdog>,
    listeners: Vec<EventListener>,
}

impl FsmEngine {
    /// Открыть движок: восстановление из WAL (F-F-05), при незавершённом
    /// переходе — принудительный RECOVERY (AC-04).
    pub fn open(
        wal_path: impl AsRef<Path>,
        config: EngineConfig,
        watchdog: Box<dyn Watchdog>,
    ) -> Result<Self, EngineError> {
        let wal_path: PathBuf = wal_path.as_ref().to_path_buf();
        let recovery = wal_recover(&wal_path)?;
        let mut wal = WalWriter::open(&wal_path, config.wal_fsync)?;

        // Восстановление последнего COMMIT'нутого состояния.
        let mut lifecycle = LifecycleState::Boot;
        let mut mode = OperatingMode::Nominal;
        let mut epoch = 0u64;
        let mut reason = String::from("cold boot");
        let mut last_trigger = TransitionTrigger::Unspecified;
        for rec in &recovery.records {
            if rec.record_type == WalRecordType::Commit {
                if let Some(t) = rec.transition() {
                    lifecycle = t.to_lifecycle;
                    mode = t.to_mode;
                    epoch = t.epoch.max(epoch);
                    reason = t.reason.clone();
                    last_trigger = t.trigger;
                }
            }
        }

        let mut write_locked = false;
        if recovery.needs_forced_recovery() {
            // AC-04: незавершённый переход / torn write → принудительный
            // RECOVERY + повтор SELF_TEST. Матрица разрешает RECOVERY только
            // с BOOT_FAILSAFE/RUNNING/DEGRADED/SHUTDOWN — из BOOT стартуем
            // в BOOT_FAILSAFE×RECOVERY (failsafe-семантика).
            reason = if recovery.mid_file_corruption {
                "WAL corruption detected (инцидент безопасности)".into()
            } else if recovery.truncated_tail {
                "WAL truncated tail (torn write) → forced RECOVERY".into()
            } else {
                "WAL dangling intent → forced RECOVERY + SELF_TEST".into()
            };
            let forced = forced_recovery_state(lifecycle);
            lifecycle = forced.0;
            mode = forced.1;
            last_trigger = TransitionTrigger::WalIncomplete;
            epoch += 1;
            let t = TransitionPayload {
                from_lifecycle: lifecycle,
                to_lifecycle: lifecycle,
                from_mode: mode,
                to_mode: mode,
                epoch,
                trigger: last_trigger,
                reason: reason.clone(),
                intent_seq: None,
            };
            let intent_seq = wal.append_intent(&t)?;
            wal.append_commit(&t, intent_seq, true)?;
        } else if recovery.mid_file_corruption {
            write_locked = true;
            reason = "WAL mid-file corruption → write lock".into();
        }

        let rollback = RollbackManager::new(UpdateSlot::A, 0);
        Ok(Self {
            lifecycle,
            mode,
            epoch,
            reason,
            last_trigger,
            write_locked,
            wal,
            recovery_info: recovery,
            rollback,
            config,
            watchdog,
            listeners: Vec::new(),
        })
    }

    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            lifecycle: self.lifecycle,
            mode: self.mode,
            epoch: self.epoch,
            wal_sequence: self.wal.next_seq().saturating_sub(1),
            timestamp_unix_ns: crate::wal::now_ns(),
            reason: self.reason.clone(),
            last_trigger: self.last_trigger,
            write_locked: self.write_locked,
        }
    }

    pub fn lifecycle(&self) -> LifecycleState {
        self.lifecycle
    }
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn write_locked(&self) -> bool {
        self.write_locked
    }
    pub fn recovery_info(&self) -> &WalRecovery {
        &self.recovery_info
    }
    pub fn wal_path(&self) -> &Path {
        self.wal.path()
    }

    pub fn add_listener(&mut self, listener: EventListener) {
        self.listeners.push(listener);
    }

    /// Запрос перехода (fsm.proto:RequestTransition).
    pub fn request_transition(
        &mut self,
        to_lifecycle: LifecycleState,
        to_mode: OperatingMode,
        trigger: TransitionTrigger,
        reason: &str,
    ) -> Result<StateEvent, EngineError> {
        self.transition_inner(to_lifecycle, to_mode, trigger, reason, true)
    }

    /// Внутренний переход; `require_unlocked=false` — для служебных
    /// RECOVERY-переходов при активной блокировке записи.
    fn transition_inner(
        &mut self,
        to_lifecycle: LifecycleState,
        to_mode: OperatingMode,
        trigger: TransitionTrigger,
        reason: &str,
        require_unlocked: bool,
    ) -> Result<StateEvent, EngineError> {
        if self.lifecycle == LifecycleState::Shutdown {
            return Err(EngineError::TerminalState);
        }
        if require_unlocked && self.write_locked
            && to_mode != OperatingMode::Recovery
        {
            return Err(EngineError::WriteLocked);
        }
        let from = (self.lifecycle, self.mode);
        let to = (to_lifecycle, to_mode);
        if !matrix_allowed(to_lifecycle, to_mode) || !transition_allowed(from, to) {
            if !matrix_allowed(to_lifecycle, to_mode) {
                return Err(EngineError::MatrixViolation {
                    from_lifecycle: from.0,
                    from_mode: from.1,
                    to_lifecycle,
                    to_mode,
                });
            }
            return Err(EngineError::EdgeViolation(from.0, to_lifecycle));
        }

        let previous = self.snapshot();
        let started = Instant::now();
        self.epoch += 1;
        let payload = TransitionPayload {
            from_lifecycle: self.lifecycle,
            to_lifecycle,
            from_mode: self.mode,
            to_mode,
            epoch: self.epoch,
            trigger,
            reason: reason.to_string(),
            intent_seq: None,
        };

        // F-F-05: intent → fsync → применение → watchdog → commit → fsync.
        let intent_seq = self.wal.append_intent(&payload)?;
        self.lifecycle = to_lifecycle;
        self.mode = to_mode;
        let ack = self.watchdog.ack(self.epoch, self.config.watchdog_timeout);
        self.wal.append_commit(&payload, intent_seq, ack)?;

        if !ack {
            // Watchdog не подтвердил в пределах NF-05 → форсированный RECOVERY.
            let forced = forced_recovery_state(self.lifecycle);
            self.lifecycle = forced.0;
            self.mode = forced.1;
            self.reason = format!("watchdog timeout → forced RECOVERY ({reason})");
            self.last_trigger = TransitionTrigger::WatchdogTimeout;
            self.epoch += 1;
            let forced_payload = TransitionPayload {
                from_lifecycle: to_lifecycle,
                to_lifecycle: self.lifecycle,
                from_mode: to_mode,
                to_mode: self.mode,
                epoch: self.epoch,
                trigger: TransitionTrigger::WatchdogTimeout,
                reason: self.reason.clone(),
                intent_seq: None,
            };
            let s = self.wal.append_intent(&forced_payload)?;
            self.wal.append_commit(&forced_payload, s, true)?;
        } else {
            self.reason = reason.to_string();
            self.last_trigger = trigger;
        }

        let event = StateEvent {
            previous,
            current: self.snapshot(),
            trigger,
            reason: reason.to_string(),
            timestamp_unix_ns: crate::wal::now_ns(),
            duration_ms: started.elapsed().as_millis() as u64,
        };
        for l in self.listeners.iter_mut() {
            l(&event);
        }
        Ok(event)
    }

    /// WORM truncation (F-G-04/AC-03): блокировка записи + RECOVERY.
    pub fn notify_worm_truncation(&mut self, detail: &str) -> Result<StateEvent, EngineError> {
        self.write_locked = true;
        let target = forced_recovery_state(self.lifecycle);
        self.transition_inner(
            target.0,
            OperatingMode::Recovery,
            TransitionTrigger::WormTruncation,
            &format!("WORM truncation: {detail}"),
            false,
        )
    }

    /// Внешний якорь WORM недоступен > 5 мин (F-G-04): DEGRADED.
    pub fn notify_ext_anchor_down(&mut self, detail: &str) -> Result<StateEvent, EngineError> {
        if self.lifecycle == LifecycleState::Running {
            self.transition_inner(
                LifecycleState::Degraded,
                OperatingMode::Isolated,
                TransitionTrigger::ExtAnchorDown,
                &format!("external WORM anchor down: {detail}"),
                true,
            )
        } else {
            Err(EngineError::EdgeViolation(self.lifecycle, LifecycleState::Degraded))
        }
    }

    /// Износ TPM NV ≥ 80% (F-G-05): DEGRADED + алерт.
    pub fn notify_tpm_wear_high(&mut self, wear_percent: f64) -> Result<StateEvent, EngineError> {
        if self.lifecycle == LifecycleState::Running {
            self.transition_inner(
                LifecycleState::Degraded,
                OperatingMode::Isolated,
                TransitionTrigger::TpmWearHigh,
                &format!("TPM NV wear {wear_percent:.1}% ≥ 80%"),
                true,
            )
        } else {
            Err(EngineError::EdgeViolation(self.lifecycle, LifecycleState::Degraded))
        }
    }

    /// Провал SELF_TEST: → BOOT_FAILSAFE×RECOVERY + вердикт rollback-менеджеру.
    pub fn notify_self_test_failed(&mut self, detail: &str) -> Result<StateEvent, EngineError> {
        self.rollback.record_self_test_verdict(false);
        let _ = self.wal.append(
            WalRecordType::SelfTestResult,
            crate::wal::FLAG_FSYNC,
            &serde_json::to_value(SelfTestPayload {
                passed: false,
                total_duration_ms: 0,
                items: vec![SelfTestItemPayload {
                    name: "notify".into(),
                    passed: false,
                    detail: detail.to_string(),
                    duration_ms: 0,
                }],
            })
            .unwrap_or(serde_json::Value::Null),
        );
        self.transition_inner(
            LifecycleState::BootFailsafe,
            OperatingMode::Recovery,
            TransitionTrigger::SelfTestFail,
            &format!("SELF_TEST failed: {detail}"),
            false,
        )
    }

    /// Успех SELF_TEST: вердикт rollback-менеджеру + запись в WAL.
    /// Переход в RUNNING вызывающий делает явно (request_transition).
    pub fn record_self_test_passed(&mut self, report: &SelfTestPayload) -> Result<(), EngineError> {
        self.rollback.record_self_test_verdict(true);
        self.wal.append(
            WalRecordType::SelfTestResult,
            crate::wal::FLAG_FSYNC,
            &serde_json::to_value(report).map_err(|e| WalError::Payload(e.to_string()))?,
        )?;
        Ok(())
    }

    // --- A/B-обновления (делегирование RollbackManager + WAL-записи) ---------

    pub fn stage_update(
        &mut self,
        slot: UpdateSlot,
        version: u64,
        artifact_blake3: &str,
        artifact: &[u8],
        signature: &[u8; 64],
        signer_pk: &[u8; 32],
    ) -> Result<RollbackStatus, EngineError> {
        self.rollback
            .stage_update(slot, version, artifact_blake3, artifact, signature, signer_pk)?;
        self.wal.append(
            WalRecordType::RollbackStage,
            crate::wal::FLAG_FSYNC,
            &serde_json::to_value(self.rollback.status())
                .map_err(|e| WalError::Payload(e.to_string()))?,
        )?;
        Ok(self.rollback.status())
    }

    pub fn commit_update(&mut self) -> Result<RollbackStatus, EngineError> {
        let committed = self.rollback.commit_update()?;
        self.wal.append(
            WalRecordType::RollbackCommit,
            crate::wal::FLAG_FSYNC,
            &serde_json::json!({
                "action": "COMMIT",
                "slot": committed.slot,
                "version": committed.version_number,
                "status": self.rollback.status(),
            }),
        )?;
        Ok(self.rollback.status())
    }

    pub fn rollback_update(&mut self, reason: &str) -> Result<RollbackStatus, EngineError> {
        self.rollback.rollback(reason)?;
        self.wal.append(
            WalRecordType::RollbackCommit,
            crate::wal::FLAG_FSYNC,
            &serde_json::json!({
                "action": "ROLLBACK",
                "reason": reason,
                "status": self.rollback.status(),
            }),
        )?;
        Ok(self.rollback.status())
    }

    pub fn rollback_status(&self) -> RollbackStatus {
        self.rollback.status()
    }

    // --- Форензика -------------------------------------------------------------

    /// zt-core-cli dump-state (runbook §2). Всегда перечитывает WAL с диска —
    /// форензика обязана отражать ТЕКУЩЕЕ состояние журнала, а не снимок
    /// момента открытия движка.
    pub fn dump_state(&self) -> serde_json::Value {
        let recovery = wal_recover(self.wal.path()).unwrap_or_default();
        let tail: Vec<serde_json::Value> = recovery
            .records
            .iter()
            .rev()
            .take(16)
            .rev()
            .map(|r| {
                serde_json::json!({
                    "seq": r.seq,
                    "type": r.record_type,
                    "flags": r.flags,
                    "ts_ns": r.ts_ns,
                    "payload": r.payload,
                    "checksum": hex_encode(&r.checksum),
                })
            })
            .collect();
        serde_json::json!({
            "snapshot": self.snapshot(),
            "rollback": self.rollback_status(),
            "wal": {
                "path": self.wal.path().display().to_string(),
                "records_total": recovery.records.len(),
                "last_seq": recovery.last_seq,
                "dangling_intent": recovery.dangling_intent.is_some(),
                "truncated_tail": recovery.truncated_tail,
                "mid_file_corruption": recovery.mid_file_corruption,
                "tail": tail,
            },
        })
    }
}

/// Выбор комбинации для форсированного RECOVERY (матрица Приложения А).
pub fn forced_recovery_state(current: LifecycleState) -> (LifecycleState, OperatingMode) {
    if matrix_allowed(current, OperatingMode::Recovery) {
        (current, OperatingMode::Recovery)
    } else {
        (LifecycleState::BootFailsafe, OperatingMode::Recovery)
    }
}

/// hex-кодирование (для форензики dump_state).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{LifecycleState as L, OperatingMode as M, TransitionTrigger as T};

    fn engine(dir: &tempfile::TempDir) -> FsmEngine {
        FsmEngine::open(
            dir.path().join("wal.log"),
            EngineConfig::default(),
            Box::new(ImmediateWatchdog),
        )
        .unwrap()
    }

    #[test]
    fn cold_boot_starts_at_boot_nominal() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(&dir);
        assert_eq!(e.lifecycle(), L::Boot);
        assert_eq!(e.mode(), M::Nominal);
        assert_eq!(e.epoch(), 0);
        assert!(!e.write_locked());
    }

    #[test]
    fn happy_path_boot_to_running() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        e.request_transition(L::SelfTest, M::Nominal, T::BootOk, "boot ok").unwrap();
        e.request_transition(L::Running, M::Nominal, T::SelfTestPass, "tests passed")
            .unwrap();
        assert_eq!(e.lifecycle(), L::Running);
        assert_eq!(e.epoch(), 2);
        assert!(e.snapshot().wal_sequence >= 4); // intent+commit ×2
    }

    #[test]
    fn matrix_violation_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        let err = e
            .request_transition(L::Boot, M::Isolated, T::Operator, "x")
            .unwrap_err();
        assert!(matches!(err, EngineError::MatrixViolation { .. }));
        // состояние не изменилось
        assert_eq!(e.lifecycle(), L::Boot);
        assert_eq!(e.mode(), M::Nominal);
    }

    #[test]
    fn edge_violation_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        // BOOT → RUNNING напрямую запрещён графом
        let err = e
            .request_transition(L::Running, M::Nominal, T::Operator, "shortcut")
            .unwrap_err();
        assert!(matches!(err, EngineError::EdgeViolation(L::Boot, L::Running)));
    }

    #[test]
    fn ac04_power_loss_mid_transition_forces_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("wal.log");
        {
            // пишем Intent БЕЗ Commit — имитация отключения питания (AC-04)
            let mut w = WalWriter::open(&wal_path, true).unwrap();
            w.append_intent(&TransitionPayload {
                from_lifecycle: L::Boot,
                to_lifecycle: L::SelfTest,
                from_mode: M::Nominal,
                to_mode: M::Nominal,
                epoch: 1,
                trigger: T::BootOk,
                reason: "power will fail here".into(),
                intent_seq: None,
            })
            .unwrap();
        }
        // старт после аварии → RECOVERY
        let e = FsmEngine::open(&wal_path, EngineConfig::default(), Box::new(ImmediateWatchdog))
            .unwrap();
        assert_eq!(e.mode(), M::Recovery, "AC-04: старт обязан быть в RECOVERY");
        assert_eq!(e.lifecycle(), L::BootFailsafe);
        assert!(e.recovery_info().needs_forced_recovery());
        // повтор SELF_TEST разрешён: BOOT_FAILSAFE×RECOVERY → SELF_TEST×NOMINAL
        let mut e = e;
        e.request_transition(L::SelfTest, M::Nominal, T::Operator, "retest")
            .unwrap();
        assert_eq!(e.lifecycle(), L::SelfTest);
    }

    #[test]
    fn committed_state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("wal.log");
        {
            let mut e = FsmEngine::open(&wal_path, EngineConfig::default(), Box::new(ImmediateWatchdog))
                .unwrap();
            e.request_transition(L::SelfTest, M::Nominal, T::BootOk, "boot ok").unwrap();
            e.request_transition(L::Running, M::Nominal, T::SelfTestPass, "pass").unwrap();
        }
        let e = FsmEngine::open(&wal_path, EngineConfig::default(), Box::new(ImmediateWatchdog))
            .unwrap();
        assert_eq!(e.lifecycle(), L::Running);
        assert_eq!(e.mode(), M::Nominal);
        assert_eq!(e.epoch(), 2);
    }

    #[test]
    fn watchdog_timeout_forces_recovery_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = FsmEngine::open(
            dir.path().join("wal.log"),
            EngineConfig::default(),
            Box::new(FlakyWatchdog { acks_left: 0 }), // watchdog «завис»
        )
        .unwrap();
        let ev = e
            .request_transition(L::SelfTest, M::Nominal, T::BootOk, "boot ok")
            .unwrap();
        assert_eq!(e.mode(), M::Recovery, "NF-05: watchdog timeout → RECOVERY");
        assert_eq!(e.lifecycle(), L::BootFailsafe);
        assert_eq!(ev.current.mode, M::Recovery);
        assert_eq!(e.snapshot().last_trigger, T::WatchdogTimeout);
    }

    #[test]
    fn worm_truncation_locks_writes_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        e.request_transition(L::SelfTest, M::Nominal, T::BootOk, "x").unwrap();
        e.request_transition(L::Running, M::Nominal, T::SelfTestPass, "x").unwrap();
        // AC-03: truncation WORM → RECOVERY + блокировка записи
        e.notify_worm_truncation("seq_local < seq_TPM").unwrap();
        assert!(e.write_locked());
        assert_eq!(e.mode(), M::Recovery);
        assert_eq!(e.lifecycle(), L::Running); // RUNNING×RECOVERY допустим матрицей
        // обычные переходы заблокированы
        assert!(matches!(
            e.request_transition(L::SelfTest, M::Nominal, T::Operator, "x"),
            Err(EngineError::WriteLocked)
        ));
    }

    #[test]
    fn anchor_down_degrades_running() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        e.request_transition(L::SelfTest, M::Nominal, T::BootOk, "x").unwrap();
        e.request_transition(L::Running, M::Nominal, T::SelfTestPass, "x").unwrap();
        e.notify_ext_anchor_down("S3 503 > 5 мин").unwrap();
        assert_eq!(e.lifecycle(), L::Degraded);
        assert_eq!(e.mode(), M::Isolated); // DEGRADED×ISOLATED по Приложению А
        e.notify_tpm_wear_high(85.0).unwrap_err(); // уже DEGRADED — ребра нет
    }

    #[test]
    fn shutdown_is_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        e.request_transition(L::Shutdown, M::Nominal, T::ShutdownRequested, "bye")
            .unwrap();
        assert!(matches!(
            e.request_transition(L::Boot, M::Nominal, T::Operator, "revive"),
            Err(EngineError::TerminalState)
        ));
    }

    #[test]
    fn listeners_receive_events() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let c2 = counter.clone();
        e.add_listener(Box::new(move |_ev| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        e.request_transition(L::SelfTest, M::Nominal, T::BootOk, "x").unwrap();
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn dump_state_contains_forensics() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = engine(&dir);
        e.request_transition(L::SelfTest, M::Nominal, T::BootOk, "x").unwrap();
        let dump = e.dump_state();
        assert_eq!(dump["snapshot"]["lifecycle"], "SELF_TEST");
        assert!(dump["wal"]["records_total"].as_u64().unwrap() >= 2);
        assert!(dump["wal"]["tail"].is_array());
        assert!(dump["rollback"]["pending_rollback_counter"].as_u64().unwrap() == 0);
    }
}
