//! Pending Rollback Counter и A/B-обновления (F-F-03, F-I-01/02/03).
//!
//! Инвариант ТЗ: **откат прошивки запрещён до успешного SELF_TEST**.
//!
//! | Событие                              | counter | rollback_allowed |
//! |--------------------------------------|---------|------------------|
//! | `stage_update(Slot B, v+1)`          | +1      | false            |
//! | SELF_TEST не завершён                | —       | false (F-F-03)   |
//! | SELF_TEST(Slot B) = pass → `commit`  | 0       | — (Slot A обновлён атомарно) |
//! | SELF_TEST(Slot B) = fail             | —       | true → rollback к Slot A    |
//!
//! Anti-downgrade (F-I-02): `version_number` монотонна; в prod хранится в
//! TPM NV (см. `persist_version`), здесь — в состоянии менеджера + WAL-запись.
//! Подпись артефакта (F-I-01): Ed25519 offline-ключом HSM.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Слоты A/B (F-I-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateSlot {
    A,
    B,
}

impl UpdateSlot {
    pub fn as_str(self) -> &'static str {
        match self {
            UpdateSlot::A => "SLOT_A",
            UpdateSlot::B => "SLOT_B",
        }
    }
}

/// Вердикт SELF_TEST для staged-обновления.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelfTestVerdict {
    Pending,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StagedUpdate {
    pub slot: UpdateSlot,
    pub version_number: u64,
    pub artifact_blake3: String,
    pub signature_verified: bool,
}

#[derive(Debug, Error)]
pub enum RollbackError {
    #[error("rollback forbidden: SELF_TEST pending (F-F-03)")]
    RollbackForbiddenPendingSelfTest,
    #[error("rollback forbidden: no staged update")]
    NothingStaged,
    #[error("commit forbidden: SELF_TEST verdict is {0:?}")]
    CommitForbidden(SelfTestVerdict),
    #[error("anti-downgrade: version {staged} <= active {active} (F-I-02)")]
    AntiDowngrade { staged: u64, active: u64 },
    #[error("stage target must be Slot B (F-I-03), got {0:?}")]
    WrongSlot(UpdateSlot),
    #[error("artifact signature invalid (F-I-01)")]
    BadSignature,
    #[error("update already staged (завершите или откатите текущее)")]
    AlreadyStaged,
}

/// Менеджер A/B-обновлений и Pending Rollback Counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackManager {
    pub pending_rollback_counter: u32,
    pub active_slot: UpdateSlot,
    pub version_active: u64,
    pub staged: Option<StagedUpdate>,
    pub verdict: SelfTestVerdict,
    pub last_rollback_reason: String,
}

impl Default for RollbackManager {
    fn default() -> Self {
        Self {
            pending_rollback_counter: 0,
            active_slot: UpdateSlot::A,
            version_active: 0,
            staged: None,
            verdict: SelfTestVerdict::Pending,
            last_rollback_reason: String::new(),
        }
    }
}

impl RollbackManager {
    pub fn new(active_slot: UpdateSlot, version_active: u64) -> Self {
        Self {
            active_slot,
            version_active,
            ..Default::default()
        }
    }

    /// Разместить обновление в Slot B (F-I-03 шаг «stage»).
    ///
    /// `signature`/`signer_public_key` — Ed25519 (F-I-01: offline-ключ HSM).
    pub fn stage_update(
        &mut self,
        slot: UpdateSlot,
        version_number: u64,
        artifact_blake3: &str,
        artifact_for_signature: &[u8],
        signature: &[u8; 64],
        signer_public_key: &[u8; 32],
    ) -> Result<(), RollbackError> {
        if slot != UpdateSlot::B {
            return Err(RollbackError::WrongSlot(slot));
        }
        if self.staged.is_some() {
            return Err(RollbackError::AlreadyStaged);
        }
        if version_number <= self.version_active {
            return Err(RollbackError::AntiDowngrade {
                staged: version_number,
                active: self.version_active,
            });
        }
        // F-I-01: проверка подписи offline-ключом
        let vk = VerifyingKey::from_bytes(signer_public_key)
            .map_err(|_| RollbackError::BadSignature)?;
        let sig = Signature::from_bytes(signature);
        use ed25519_dalek::Verifier;
        vk.verify(artifact_for_signature, &sig)
            .map_err(|_| RollbackError::BadSignature)?;

        self.staged = Some(StagedUpdate {
            slot,
            version_number,
            artifact_blake3: artifact_blake3.to_string(),
            signature_verified: true,
        });
        self.pending_rollback_counter += 1;
        self.verdict = SelfTestVerdict::Pending;
        Ok(())
    }

    /// Зафиксировать вердикт SELF_TEST staged-слота.
    pub fn record_self_test_verdict(&mut self, passed: bool) {
        if self.staged.is_some() {
            self.verdict = if passed {
                SelfTestVerdict::Passed
            } else {
                SelfTestVerdict::Failed
            };
        }
    }

    /// Разрешён ли rollback СЕЙЧАС (инвариант F-F-03).
    pub fn rollback_allowed(&self) -> bool {
        match (&self.staged, self.verdict) {
            // staged + вердикт ещё не вынесен → откат ЗАПРЕЩЁН
            (Some(_), SelfTestVerdict::Pending) => false,
            // SELF_TEST провален → откат разрешён и обязателен
            (Some(_), SelfTestVerdict::Failed) => true,
            // после успешного commit/rollback staged очищен
            (None, _) => false,
            // staged + Passed: ожидается commit, не rollback
            (Some(_), SelfTestVerdict::Passed) => false,
        }
    }

    /// Атомарный commit Slot B → Slot A (F-I-03): только после Passed.
    pub fn commit_update(&mut self) -> Result<StagedUpdate, RollbackError> {
        if self.verdict != SelfTestVerdict::Passed {
            return Err(RollbackError::CommitForbidden(self.verdict));
        }
        let staged = self.staged.take().ok_or(RollbackError::NothingStaged)?;
        self.active_slot = staged.slot;
        self.version_active = staged.version_number;
        self.pending_rollback_counter = 0;
        self.verdict = SelfTestVerdict::Pending;
        Ok(staged)
    }

    /// Rollback к Slot A: только при провале SELF_TEST (F-F-03/F-I-03).
    pub fn rollback(&mut self, reason: &str) -> Result<(), RollbackError> {
        if self.staged.is_none() {
            return Err(RollbackError::NothingStaged);
        }
        if !self.rollback_allowed() {
            return Err(RollbackError::RollbackForbiddenPendingSelfTest);
        }
        self.staged = None;
        self.pending_rollback_counter = 0;
        self.active_slot = UpdateSlot::A;
        self.verdict = SelfTestVerdict::Pending;
        self.last_rollback_reason = reason.to_string();
        Ok(())
    }

    /// Статус для fsm.proto:RollbackStatus.
    pub fn status(&self) -> RollbackStatus {
        RollbackStatus {
            pending_rollback_counter: self.pending_rollback_counter,
            rollback_allowed: self.rollback_allowed(),
            active_slot: self.active_slot,
            staged_slot: self.staged.as_ref().map(|s| s.slot),
            version_number_active: self.version_active,
            version_number_staged: self.staged.as_ref().map(|s| s.version_number).unwrap_or(0),
            verdict: self.verdict,
            reason: self.last_rollback_reason.clone(),
        }
    }
}

/// fsm.proto:RollbackStatus (wire-совместимый JSON).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RollbackStatus {
    pub pending_rollback_counter: u32,
    pub rollback_allowed: bool,
    pub active_slot: UpdateSlot,
    pub staged_slot: Option<UpdateSlot>,
    pub version_number_active: u64,
    pub version_number_staged: u64,
    pub verdict: SelfTestVerdict,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const OFFLINE_SEED: [u8; 32] = *b"zt-offline-hsm-signing-key-00001";

    fn signed_artifact(content: &[u8]) -> (Vec<u8>, [u8; 64], [u8; 32]) {
        let sk = SigningKey::from_bytes(&OFFLINE_SEED);
        let sig = sk.sign(content);
        (content.to_vec(), sig.to_bytes(), sk.verifying_key().to_bytes())
    }

    fn staged(m: &mut RollbackManager, version: u64) {
        let (artifact, sig, pk) = signed_artifact(format!("fw-v{version}").as_bytes());
        m.stage_update(UpdateSlot::B, version, "blake3:artifact", &artifact, &sig, &pk)
            .unwrap();
    }

    #[test]
    fn default_state() {
        let m = RollbackManager::new(UpdateSlot::A, 5);
        assert_eq!(m.pending_rollback_counter, 0);
        assert!(!m.rollback_allowed());
        assert_eq!(m.version_active, 5);
    }

    #[test]
    fn stage_requires_slot_b() {
        let mut m = RollbackManager::new(UpdateSlot::A, 1);
        let (artifact, sig, pk) = signed_artifact(b"fw");
        let err = m
            .stage_update(UpdateSlot::A, 2, "h", &artifact, &sig, &pk)
            .unwrap_err();
        assert!(matches!(err, RollbackError::WrongSlot(UpdateSlot::A)));
    }

    #[test]
    fn stage_requires_valid_signature() {
        let mut m = RollbackManager::new(UpdateSlot::A, 1);
        let (_artifact, sig, pk) = signed_artifact(b"fw-v2");
        let err = m
            .stage_update(UpdateSlot::B, 2, "h", b"tampered-artifact", &sig, &pk)
            .unwrap_err();
        assert!(matches!(err, RollbackError::BadSignature));
        assert!(m.staged.is_none());
    }

    #[test]
    fn anti_downgrade_blocks_old_version() {
        let mut m = RollbackManager::new(UpdateSlot::A, 10);
        let (artifact, sig, pk) = signed_artifact(b"fw-v9");
        let err = m
            .stage_update(UpdateSlot::B, 9, "h", &artifact, &sig, &pk)
            .unwrap_err();
        assert!(matches!(err, RollbackError::AntiDowngrade { staged: 9, active: 10 }));
        let err = m
            .stage_update(UpdateSlot::B, 10, "h", &artifact, &sig, &pk)
            .unwrap_err();
        assert!(matches!(err, RollbackError::AntiDowngrade { .. }));
    }

    #[test]
    fn ff03_rollback_forbidden_until_self_test() {
        let mut m = RollbackManager::new(UpdateSlot::A, 1);
        staged(&mut m, 2);
        assert_eq!(m.pending_rollback_counter, 1);
        // вердикта нет → rollback ЗАПРЕЩЁН (F-F-03)
        assert!(!m.rollback_allowed());
        let err = m.rollback("попытка преждевременного отката").unwrap_err();
        assert!(matches!(err, RollbackError::RollbackForbiddenPendingSelfTest));
        // commit тоже запрещён до SELF_TEST
        assert!(matches!(m.commit_update(), Err(RollbackError::CommitForbidden(SelfTestVerdict::Pending))));
    }

    #[test]
    fn self_test_fail_allows_and_performs_rollback() {
        let mut m = RollbackManager::new(UpdateSlot::A, 1);
        staged(&mut m, 2);
        m.record_self_test_verdict(false);
        assert!(m.rollback_allowed());
        m.rollback("SELF_TEST failed in slot B").unwrap();
        assert_eq!(m.pending_rollback_counter, 0);
        assert_eq!(m.active_slot, UpdateSlot::A);
        assert_eq!(m.version_active, 1, "версия активного слота не меняется при откате");
        assert!(m.staged.is_none());
    }

    #[test]
    fn self_test_pass_commits_atomically() {
        let mut m = RollbackManager::new(UpdateSlot::A, 1);
        staged(&mut m, 2);
        m.record_self_test_verdict(true);
        assert!(!m.rollback_allowed(), "после Passed ожидается commit, не rollback");
        let committed = m.commit_update().unwrap();
        assert_eq!(committed.version_number, 2);
        assert_eq!(m.active_slot, UpdateSlot::B);
        assert_eq!(m.version_active, 2);
        assert_eq!(m.pending_rollback_counter, 0);
    }

    #[test]
    fn double_stage_rejected() {
        let mut m = RollbackManager::new(UpdateSlot::A, 1);
        staged(&mut m, 2);
        let (artifact, sig, pk) = signed_artifact(b"fw-v3");
        let err = m
            .stage_update(UpdateSlot::B, 3, "h", &artifact, &sig, &pk)
            .unwrap_err();
        assert!(matches!(err, RollbackError::AlreadyStaged));
    }

    #[test]
    fn status_snapshot_matches_proto_fields() {
        let mut m = RollbackManager::new(UpdateSlot::A, 7);
        staged(&mut m, 8);
        let s = m.status();
        assert_eq!(s.pending_rollback_counter, 1);
        assert!(!s.rollback_allowed);
        assert_eq!(s.staged_slot, Some(UpdateSlot::B));
        assert_eq!(s.version_number_staged, 8);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["active_slot"], "A");
        assert_eq!(json["verdict"], "PENDING");
    }
}
