//! Чекпоинты WORM-цепочки (F-G-04): публикация по порогу
//! «≥ 1000 записей ИЛИ ≥ 60 секунд», Ed25519-подпись head'а.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::record::{hex_encode, now_unix_ns};

/// Хэш чекпоинта: BLAKE3(first_seq ‖ last_seq ‖ chain_head ‖ timestamp).
pub fn checkpoint_hash(first_seq: u64, last_seq: u64, chain_head: &[u8; 32], timestamp_ns: i64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&first_seq.to_be_bytes());
    hasher.update(&last_seq.to_be_bytes());
    hasher.update(chain_head);
    hasher.update(&(timestamp_ns as u64).to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Чекпоинт (audit.proto:Checkpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub first_seq: u64,
    pub last_seq: u64,
    pub chain_head: String,   // hex
    pub timestamp_unix_ns: i64,
    pub checkpoint_hash: String, // hex
    pub ed25519_signature: String, // hex
    pub signer_public_key: String, // hex
}

impl Checkpoint {
    pub fn chain_head_bytes(&self) -> Result<[u8; 32], String> {
        crate::record::hex_decode(&self.chain_head)
    }

    pub fn signature_bytes(&self) -> Result<[u8; 64], String> {
        crate::record::hex_decode(&self.ed25519_signature)
    }

    /// Верификация подписи чекпоинта публичным ключом (hex).
    pub fn verify(&self) -> Result<bool, String> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pk: [u8; 32] = crate::record::hex_decode(&self.signer_public_key)?;
        let sig: [u8; 64] = crate::record::hex_decode(&self.ed25519_signature)?;
        let hash: [u8; 32] = crate::record::hex_decode(&self.checkpoint_hash)?;
        let expected = checkpoint_hash(
            self.first_seq,
            self.last_seq,
            &self.chain_head_bytes()?,
            self.timestamp_unix_ns,
        );
        if expected != hash {
            return Ok(false);
        }
        let vk = VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;
        Ok(vk.verify(&hash, &Signature::from_bytes(&sig)).is_ok())
    }
}

/// Политика публикации чекпоинтов (F-G-04: ≥1000 записей ИЛИ ≥60 секунд).
#[derive(Debug, Clone)]
pub struct CheckpointPolicy {
    pub every_records: u64,
    pub every_interval: Duration,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            every_records: 1000,
            every_interval: Duration::from_secs(60),
        }
    }
}

/// Трекер «созрел ли чекпоинт».
pub struct CheckpointScheduler {
    policy: CheckpointPolicy,
    last_checkpoint_seq: u64,
    last_checkpoint_at: Instant,
}

impl CheckpointScheduler {
    pub fn new(policy: CheckpointPolicy, current_seq: u64) -> Self {
        Self {
            policy,
            last_checkpoint_seq: current_seq,
            last_checkpoint_at: Instant::now(),
        }
    }

    /// Созрел ли чекпоинт для текущего seq.
    /// `current_seq` — seq последней записанной записи;
    /// `last_checkpoint_seq` — seq, до которого покрыто последним чекпоинтом.
    pub fn is_due(&self, current_seq: u64) -> bool {
        self.records_since(current_seq) >= self.policy.every_records
            || self.last_checkpoint_at.elapsed() >= self.policy.every_interval
    }

    /// Отметить публикацию.
    pub fn mark_published(&mut self, seq: u64) {
        self.last_checkpoint_seq = seq;
        self.last_checkpoint_at = Instant::now();
    }

    pub fn records_since(&self, current_seq: u64) -> u64 {
        current_seq.saturating_sub(self.last_checkpoint_seq)
    }

    pub fn elapsed(&self) -> Duration {
        self.last_checkpoint_at.elapsed()
    }
}

/// Сформировать и подписать чекпоинт (подпись — через ChainSigner,
/// в prod ключ живёт в TPM: F-H-03, Приложение Б п.3).
pub fn create_checkpoint(
    first_seq: u64,
    last_seq: u64,
    chain_head: &[u8; 32],
    signer: &dyn crate::chain::ChainSigner,
) -> Checkpoint {
    let ts = now_unix_ns();
    let hash = checkpoint_hash(first_seq, last_seq, chain_head, ts);
    let sig = signer.sign(&hash);
    Checkpoint {
        first_seq,
        last_seq,
        chain_head: hex_encode(chain_head),
        timestamp_unix_ns: ts,
        checkpoint_hash: hex_encode(&hash),
        ed25519_signature: hex_encode(&sig),
        signer_public_key: hex_encode(&signer.verifying_key()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::SeedSigner;

    fn signer() -> SeedSigner {
        SeedSigner::from_seed(*b"zt-worm-checkpoint-test-seed0001")
    }

    #[test]
    fn checkpoint_hash_construction() {
        let head = [4u8; 32];
        let h1 = checkpoint_hash(1, 1000, &head, 100);
        let h2 = checkpoint_hash(1, 1000, &head, 100);
        let h3 = checkpoint_hash(1, 1001, &head, 100);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        // независимая ручная сборка
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u64.to_be_bytes());
        buf.extend_from_slice(&1000u64.to_be_bytes());
        buf.extend_from_slice(&head);
        buf.extend_from_slice(&100u64.to_be_bytes());
        assert_eq!(h1, *blake3::hash(&buf).as_bytes());
    }

    #[test]
    fn checkpoint_signature_verifies_and_detects_tamper() {
        let s = signer();
        let cp = create_checkpoint(1, 42, &[9u8; 32], &s);
        assert!(cp.verify().unwrap());
        let mut tampered = cp.clone();
        tampered.last_seq = 43;
        assert!(!tampered.verify().unwrap(), "подмена last_seq обязана ловиться");
        let mut t2 = cp.clone();
        t2.chain_head = hex_encode(&[1u8; 32]);
        assert!(!t2.verify().unwrap());
    }

    #[test]
    fn scheduler_triggers_on_records_threshold() {
        let policy = CheckpointPolicy { every_records: 1000, every_interval: Duration::from_secs(3600) };
        let sched = CheckpointScheduler::new(policy, 0);
        assert!(!sched.is_due(999));
        assert!(sched.is_due(1000));
        assert!(sched.is_due(1500));
    }

    #[test]
    fn scheduler_triggers_on_time_threshold() {
        let policy = CheckpointPolicy { every_records: u64::MAX, every_interval: Duration::from_millis(50) };
        let sched = CheckpointScheduler::new(policy, 0);
        assert!(!sched.is_due(10));
        std::thread::sleep(Duration::from_millis(80));
        assert!(sched.is_due(10), "≥ 60 с (здесь 50 мс) с прошлого чекпоинта → публикация");
    }

    #[test]
    fn scheduler_resets_after_publish() {
        let policy = CheckpointPolicy { every_records: 5, every_interval: Duration::from_secs(3600) };
        let mut sched = CheckpointScheduler::new(policy, 0);
        assert!(sched.is_due(5));
        sched.mark_published(5);
        assert!(!sched.is_due(6));
        assert!(sched.is_due(10));
    }
}
