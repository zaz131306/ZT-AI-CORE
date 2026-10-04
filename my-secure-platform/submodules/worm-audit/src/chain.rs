//! Append-only цепочка WORM (F-G-01…03, NF-03).
//!
//! * хранение: JSONL-файл, открытие только на допись (`O_APPEND`);
//! * anti-replay (F-G-03): кэш nonce с TTL-окном + контроль часов;
//! * подпись каждой записи: Ed25519 через [`ChainSigner`] (в prod — ключ
//!   в TPM/HSM, F-H-03; в dev — файловый провайдер);
//! * синхронизация: [`SyncPolicy`] (NF-03 ≥ 10 000 записей/с достигается
//!   group-commit; `EveryRecord` — максимальная стойкость);
//! * верификация: пересчёт chain_hash + опционально подписей.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::record::{
    chain_hash, generate_nonce, now_unix_ns, payload_hash, AuditRecord, RecordKind,
    GENESIS_HASH,
};

/// Подписывающий интерфейс (F-H-03: приватный ключ не покидает TPM/HSM;
/// файловая реализация — только dev/CI).
pub trait ChainSigner: Send {
    fn sign(&self, message: &[u8]) -> [u8; 64];
    fn verifying_key(&self) -> [u8; 32];
}

/// Dev/CI-подписант: Ed25519-ключ из 32-байтного seed.
#[derive(Debug)]
pub struct SeedSigner {
    signing: ed25519_dalek::SigningKey,
}

impl SeedSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { signing: ed25519_dalek::SigningKey::from_bytes(&seed) }
    }

    /// Загрузить seed из файла (0600) или сгенерировать и сохранить.
    pub fn load_or_create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let seed: [u8; 32] = match std::fs::read(path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&bytes);
                s
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "signing key file must contain exactly 32 bytes (seed)",
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // getrandom(2) — единственный источник случайности
                let mut s = [0u8; 32];
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_getrandom,
                        s.as_mut_ptr() as *mut libc::c_void,
                        s.len(),
                        0u32,
                    )
                };
                if rc != 32 {
                    return Err(std::io::Error::other("getrandom failed"));
                }
                std::fs::write(path, s)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                }
                s
            }
            Err(e) => return Err(e),
        };
        Ok(Self::from_seed(seed))
    }
}

impl ChainSigner for SeedSigner {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing.sign(message).to_bytes()
    }
    fn verifying_key(&self) -> [u8; 32] {
        use ed25519_dalek::VerifyingKey;
        let vk: &VerifyingKey = &self.signing.verifying_key();
        vk.to_bytes()
    }
}

/// Политика синхронизации с носителем (docs/07-worm-audit.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicy {
    /// fsync каждой записи (максимальная стойкость, низкая скорость).
    EveryRecord,
    /// Групповой fsync: каждые `max_records` или `max_interval_ms`.
    GroupCommit { max_records: usize, max_interval_ms: u64 },
    /// fsync только при публикации чекпоинта (стенды).
    OnCheckpoint,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        SyncPolicy::GroupCommit { max_records: 1000, max_interval_ms: 100 }
    }
}

impl SyncPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "every_record" => Some(SyncPolicy::EveryRecord),
            "group_commit" => Some(Self::default()),
            "on_checkpoint" => Some(SyncPolicy::OnCheckpoint),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncPolicy::EveryRecord => "every_record",
            SyncPolicy::GroupCommit { .. } => "group_commit",
            SyncPolicy::OnCheckpoint => "on_checkpoint",
        }
    }
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("duplicate nonce within TTL window (F-G-03 anti-replay)")]
    DuplicateNonce,
    #[error("timestamp {ts_ns} outside ±{window_secs}s window (clock skew / replay)")]
    ClockSkew { ts_ns: i64, window_secs: i64 },
    #[error("write locked: WORM truncation detected (F-G-04)")]
    WriteLocked,
    #[error("seq gap: expected {expected}, file has {actual}")]
    SeqGap { expected: u64, actual: u64 },
    #[error("record {seq} corrupt: {reason}")]
    Corrupt { seq: u64, reason: String },
    #[error("serialization: {0}")]
    Serde(String),
}

/// Кэш nonce для anti-replay (F-G-03): TTL-окно, «свежие» nonce не
/// вытесняются никогда.
pub struct NonceCache {
    window: Duration,
    seen: HashMap<[u8; 16], Instant>,
    last_cleanup: Instant,
}

impl NonceCache {
    pub fn new(window: Duration) -> Self {
        Self { window, seen: HashMap::new(), last_cleanup: Instant::now() }
    }

    /// Проверить и зарегистрировать nonce; false — дубликат в пределах окна.
    pub fn check_and_insert(&mut self, nonce: &[u8; 16]) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) > self.window {
            self.seen.retain(|_, t| now.duration_since(*t) <= self.window);
            self.last_cleanup = now;
        }
        if let Some(t) = self.seen.get(nonce) {
            if now.duration_since(*t) <= self.window {
                return false;
            }
        }
        self.seen.insert(*nonce, now);
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Конфигурация цепочки.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub sync_policy: SyncPolicy,
    /// TTL-окно anti-replay (F-G-03), сек.
    pub nonce_ttl: Duration,
    /// Допустимый skew часов для timestamp записи.
    pub clock_skew_tolerance: Duration,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            sync_policy: SyncPolicy::default(),
            nonce_ttl: Duration::from_secs(300),
            clock_skew_tolerance: Duration::from_secs(300),
        }
    }
}

/// Статистика производительности (NF-03).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChainStats {
    pub total_records: u64,
    pub bytes_written: u64,
    pub appends_since_sync: usize,
    pub last_sync_elapsed_ms: u64,
    pub nonce_cache_size: usize,
}

/// Append-only писатель BLAKE3-цепочки.
pub struct ChainWriter {
    path: PathBuf,
    file: File,
    writer: BufWriter<File>,
    seq: u64,
    head: [u8; 32],
    #[allow(dead_code)]
    last_ts: i64,
    nonces: NonceCache,
    config: ChainConfig,
    signer: Box<dyn ChainSigner>,
    write_locked: bool,
    since_sync: usize,
    last_sync: Instant,
    total_bytes: u64,
    last_sync_elapsed_ms: u64,
}

impl ChainWriter {
    /// Открыть существующую цепочку или создать новую.
    /// Последний валидный record восстанавливает seq/head.
    pub fn open(
        path: impl AsRef<Path>,
        config: ChainConfig,
        signer: Box<dyn ChainSigner>,
    ) -> Result<Self, ChainError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Восстановление хвоста: seq + head из последней записи.
        let (seq, head, last_ts) = match scan_last_record(&path)? {
            Some(last) => (last.seq + 1, last.chain_hash, last.timestamp_unix_ns),
            None => (1, GENESIS_HASH, 0),
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let writer = BufWriter::new(file.try_clone()?);
        let total_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            file,
            writer,
            seq,
            head,
            last_ts,
            nonces: NonceCache::new(config.nonce_ttl),
            config,
            signer,
            write_locked: false,
            since_sync: 0,
            last_sync: Instant::now(),
            total_bytes,
            last_sync_elapsed_ms: 0,
        })
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn head(&self) -> [u8; 32] {
        self.head
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn signer(&self) -> &dyn ChainSigner {
        self.signer.as_ref()
    }
    pub fn write_locked(&self) -> bool {
        self.write_locked
    }

    /// F-G-04: блокировка записи при подтверждённом truncation.
    pub fn set_write_locked(&mut self, locked: bool) {
        self.write_locked = locked;
    }

    /// Добавить запись (полный контроль: nonce, часы, блокировка, подпись).
    pub fn append(
        &mut self,
        payload: &[u8],
        kind: RecordKind,
        source: &str,
        subject: &str,
        nonce_override: Option<[u8; 16]>,
        ts_override: Option<i64>,
    ) -> Result<AuditRecord, ChainError> {
        if self.write_locked {
            return Err(ChainError::WriteLocked);
        }
        let nonce = nonce_override.unwrap_or_else(generate_nonce);
        if !self.nonces.check_and_insert(&nonce) {
            return Err(ChainError::DuplicateNonce);
        }
        let ts = ts_override.unwrap_or_else(now_unix_ns);
        let now = now_unix_ns();
        let skew = self.config.clock_skew_tolerance.as_nanos() as i64;
        if ts > now + skew || ts < now - skew {
            return Err(ChainError::ClockSkew {
                ts_ns: ts,
                window_secs: self.config.clock_skew_tolerance.as_secs() as i64,
            });
        }

        let ph = payload_hash(payload);
        let ch = chain_hash(&self.head, &ph, ts, &nonce);
        let mut record = AuditRecord {
            seq: self.seq,
            payload_hash: ph,
            timestamp_unix_ns: ts,
            nonce,
            previous_hash: self.head,
            record_signature: [0u8; 64],
            chain_hash: ch,
            kind,
            source: source.to_string(),
            subject: subject.to_string(),
        };
        // Подпись покрывает всю семантику записи кроме самого поля подписи.
        let to_sign = signature_message(&record);
        record.record_signature = self.signer.sign(&to_sign);

        let line = serde_json::to_string(&record)
            .map_err(|e| ChainError::Serde(e.to_string()))?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.total_bytes += line.len() as u64 + 1;

        self.seq += 1;
        self.head = ch;
        self.last_ts = ts;
        self.since_sync += 1;
        self.maybe_sync()?;
        Ok(record)
    }

    fn maybe_sync(&mut self) -> Result<(), ChainError> {
        // Flush (userspace -> ядро) — ВСЕГДА: запись должна быть немедленно
        // видна верификатору/читателям. FSYNC (гарантия устойчивости на носителе) —
        // по политике синхронизации (NF-03: group-commit для >= 10k rec/s).
        self.writer.flush()?;
        let due = match self.config.sync_policy {
            SyncPolicy::EveryRecord => true,
            SyncPolicy::GroupCommit { max_records, max_interval_ms } => {
                self.since_sync >= max_records
                    || self.last_sync.elapsed() >= Duration::from_millis(max_interval_ms)
            }
            SyncPolicy::OnCheckpoint => false,
        };
        if due {
            self.sync_now()?;
        }
        Ok(())
    }

    /// Принудительный flush+fsync (вызывается и при публикации чекпоинта).
    pub fn sync_now(&mut self) -> Result<(), ChainError> {
        let started = Instant::now();
        self.writer.flush()?;
        self.file.sync_all()?;
        self.since_sync = 0;
        self.last_sync = Instant::now();
        self.last_sync_elapsed_ms = started.elapsed().as_millis() as u64;
        Ok(())
    }

    pub fn stats(&self) -> ChainStats {
        ChainStats {
            total_records: self.seq.saturating_sub(1),
            bytes_written: self.total_bytes,
            appends_since_sync: self.since_sync,
            last_sync_elapsed_ms: self.last_sync_elapsed_ms,
            nonce_cache_size: self.nonces.len(),
        }
    }
}

/// Сообщение, покрываемое подписью записи (детерминированная каноническая
/// сериализация всех полей кроме record_signature).
pub fn signature_message(record: &AuditRecord) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(&record.seq.to_be_bytes());
    buf.extend_from_slice(&record.payload_hash);
    buf.extend_from_slice(&(record.timestamp_unix_ns as u64).to_be_bytes());
    buf.extend_from_slice(&record.nonce);
    buf.extend_from_slice(&record.previous_hash);
    buf.extend_from_slice(&record.chain_hash);
    buf.extend_from_slice(format!("{:?}", record.kind).as_bytes());
    buf.extend_from_slice(record.source.as_bytes());
    buf.extend_from_slice(record.subject.as_bytes());
    buf
}

/// Прочитать последнюю валидную запись файла (для восстановления seq/head).
fn scan_last_record(path: &Path) -> Result<Option<AuditRecord>, ChainError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ChainError::Io(e)),
    };
    let reader = BufReader::new(file);
    let mut last: Option<AuditRecord> = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(&line) {
            Ok(rec) => last = Some(rec),
            Err(_) => break, // оборванный хвост — последние полные записи валидны
        }
    }
    Ok(last)
}

/// Прочитать seq, с которого продолжится цепочка (без открытия писателя).
pub fn peek_next_seq(path: impl AsRef<Path>) -> Result<u64, ChainError> {
    Ok(match scan_last_record(path.as_ref())? {
        Some(last) => last.seq + 1,
        None => 1,
    })
}

/// Итератор записей цепочки (ленивый, построчный).
pub struct ChainIter {
    reader: BufReader<File>,
    next_seq: u64,
}

impl ChainIter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChainError> {
        match File::open(path.as_ref()) {
            Ok(f) => Ok(Self { reader: BufReader::new(f), next_seq: 1 }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                reader: BufReader::new(File::open("/dev/null")?),
                next_seq: 1,
            }),
            Err(e) => Err(ChainError::Io(e)),
        }
    }
}

impl Iterator for ChainIter {
    type Item = Result<AuditRecord, ChainError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {}
                Err(e) => return Some(Err(ChainError::Io(e))),
            }
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditRecord>(line.trim()) {
                Ok(rec) => {
                    if rec.seq != self.next_seq {
                        return Some(Err(ChainError::SeqGap {
                            expected: self.next_seq,
                            actual: rec.seq,
                        }));
                    }
                    self.next_seq += 1;
                    return Some(Ok(rec));
                }
                Err(e) => {
                    return Some(Err(ChainError::Corrupt {
                        seq: self.next_seq,
                        reason: e.to_string(),
                    }))
                }
            }
        }
    }
}

/// Отчёт верификации (audit.proto:VerifyChainReport).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyReport {
    pub valid: bool,
    pub records_checked: u64,
    pub first_bad_seq: u64,
    pub error: String,
    pub recomputed_head: String,
    pub duration_ms: u64,
}

/// Верификация цепочки: последовательность seq, связка previous/chain,
/// пересчёт chain_hash (deep), проверка подписей.
pub fn verify_chain(
    path: impl AsRef<Path>,
    deep: bool,
    verify_signatures: bool,
    signer: Option<&dyn ChainSigner>,
    from_seq: u64,
    to_seq: u64,
) -> VerifyReport {
    let started = Instant::now();
    let mut report = VerifyReport { valid: true, ..Default::default() };
    let mut expected_prev = GENESIS_HASH;
    let mut iter = match ChainIter::open(path.as_ref()) {
        Ok(i) => i,
        Err(e) => {
            report.valid = false;
            report.error = e.to_string();
            return report;
        }
    };
    for item in iter.by_ref() {
        let rec = match item {
            Ok(r) => r,
            Err(e) => {
                report.valid = false;
                report.first_bad_seq = report.records_checked + 1;
                report.error = e.to_string();
                return report;
            }
        };
        if to_seq > 0 && rec.seq > to_seq {
            break;
        }
        if from_seq > 0 && rec.seq < from_seq {
            expected_prev = rec.chain_hash;
            continue;
        }
        if rec.previous_hash != expected_prev {
            report.valid = false;
            report.first_bad_seq = rec.seq;
            report.error = "previous_hash mismatch (обрыв/подмена цепи)".into();
            return report;
        }
        if deep {
            let recomputed =
                chain_hash(&rec.previous_hash, &rec.payload_hash, rec.timestamp_unix_ns, &rec.nonce);
            if recomputed != rec.chain_hash {
                report.valid = false;
                report.first_bad_seq = rec.seq;
                report.error = "chain_hash mismatch (подмена записи)".into();
                return report;
            }
        }
        if verify_signatures {
            if let Some(signer) = signer {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let vk = match VerifyingKey::from_bytes(&signer.verifying_key()) {
                    Ok(vk) => vk,
                    Err(e) => {
                        report.valid = false;
                        report.error = format!("bad verifying key: {e}");
                        return report;
                    }
                };
                let sig = Signature::from_bytes(&rec.record_signature);
                if vk.verify(&signature_message(&rec), &sig).is_err() {
                    report.valid = false;
                    report.first_bad_seq = rec.seq;
                    report.error = "record signature invalid".into();
                    return report;
                }
            }
        }
        expected_prev = rec.chain_hash;
        report.records_checked += 1;
        report.recomputed_head = crate::record::hex_encode(&rec.chain_hash);
    }
    report.duration_ms = started.elapsed().as_millis() as u64;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Box<dyn ChainSigner> {
        Box::new(SeedSigner::from_seed(*b"zt-worm-audit-test-seed-00000001"))
    }

    fn chain(dir: &tempfile::TempDir, cfg: ChainConfig) -> ChainWriter {
        ChainWriter::open(dir.path().join("chain.jsonl"), cfg, signer()).unwrap()
    }

    #[test]
    fn append_builds_linked_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = chain(&dir, ChainConfig::default());
        let r1 = w.append(b"one", RecordKind::Prompt, "rag", "d8", None, None).unwrap();
        let r2 = w.append(b"two", RecordKind::Response, "rag", "d8", None, None).unwrap();
        assert_eq!(r1.previous_hash, GENESIS_HASH);
        assert_eq!(r2.previous_hash, r1.chain_hash);
        assert_eq!(r1.seq, 1);
        assert_eq!(r2.seq, 2);
        assert_eq!(w.seq(), 3);
        assert_eq!(w.head(), r2.chain_hash);
    }

    #[test]
    fn chain_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        {
            let mut w = ChainWriter::open(&path, ChainConfig::default(), signer()).unwrap();
            w.append(b"a", RecordKind::Ipc, "s", "x", None, None).unwrap();
            w.append(b"b", RecordKind::Ipc, "s", "x", None, None).unwrap();
            w.sync_now().unwrap();
        }
        let mut w = ChainWriter::open(&path, ChainConfig::default(), signer()).unwrap();
        assert_eq!(w.seq(), 3);
        let r3 = w.append(b"c", RecordKind::Ipc, "s", "x", None, None).unwrap();
        assert_eq!(r3.seq, 3);
        let report = verify_chain(&path, true, true, Some(w.signer()), 0, 0);
        assert!(report.valid, "{:?}", report);
        assert_eq!(report.records_checked, 3);
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = chain(&dir, ChainConfig::default());
        let nonce = [5u8; 16];
        w.append(b"x", RecordKind::Prompt, "s", "u", Some(nonce), None).unwrap();
        let err = w
            .append(b"y", RecordKind::Prompt, "s", "u", Some(nonce), None)
            .unwrap_err();
        assert!(matches!(err, ChainError::DuplicateNonce));
    }

    #[test]
    fn clock_skew_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = chain(&dir, ChainConfig::default());
        let future = now_unix_ns() + Duration::from_secs(3600).as_nanos() as i64;
        let err = w
            .append(b"x", RecordKind::Prompt, "s", "u", None, Some(future))
            .unwrap_err();
        assert!(matches!(err, ChainError::ClockSkew { .. }));
        let past = now_unix_ns() - Duration::from_secs(3600).as_nanos() as i64;
        assert!(matches!(
            w.append(b"x", RecordKind::Prompt, "s", "u", None, Some(past)),
            Err(ChainError::ClockSkew { .. })
        ));
    }

    #[test]
    fn write_lock_blocks_append() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = chain(&dir, ChainConfig::default());
        w.set_write_locked(true);
        let err = w.append(b"x", RecordKind::Prompt, "s", "u", None, None).unwrap_err();
        assert!(matches!(err, ChainError::WriteLocked));
    }

    #[test]
    fn tamper_detection_payload_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        {
            let mut w = ChainWriter::open(&path, ChainConfig::default(), signer()).unwrap();
            for i in 0..5 {
                w.append(format!("record-{i}").as_bytes(), RecordKind::Prompt, "s", "u", None, None)
                    .unwrap();
            }
            w.sync_now().unwrap();
        }
        // подмена payload_hash во второй записи (симуляция tampering)
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        // меняем payload_hash второй записи на другой валидный hex
        let mut rec: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        rec["payload_hash"] = serde_json::Value::String("00".repeat(32));
        lines[1] = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = verify_chain(&path, true, false, None, 0, 0);
        assert!(!report.valid);
        assert_eq!(report.first_bad_seq, 2);
        assert!(report.error.contains("chain_hash mismatch"), "{}", report.error);
    }

    #[test]
    fn signature_verification_detects_field_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        {
            let mut w = ChainWriter::open(&path, ChainConfig::default(), signer()).unwrap();
            w.append(b"secret", RecordKind::Prompt, "s", "u", None, None).unwrap();
            w.sync_now().unwrap();
        }
        // подмена source (chain_hash не затрагивается — ловит только подпись)
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replacen("\"source\":\"s\"", "\"source\":\"evil\"", 1);
        assert_ne!(text, tampered, "test setup: поле source должно существовать");
        std::fs::write(&path, tampered).unwrap();
        let s = signer();
        let report = verify_chain(&path, false, true, Some(s.as_ref()), 0, 0);
        assert!(!report.valid);
        assert!(report.error.contains("signature"), "{}", report.error);
    }

    #[test]
    fn truncation_breaks_chain_from_point() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        {
            let mut w = ChainWriter::open(&path, ChainConfig::default(), signer()).unwrap();
            for i in 0..10 {
                w.append(format!("r{i}").as_bytes(), RecordKind::Prompt, "s", "u", None, None)
                    .unwrap();
            }
            w.sync_now().unwrap();
        }
        // AC-03: удаление хвоста — цепочка остаётся валидной, но короче;
        // факт усечения детектируется СВЕРКОЙ С ЯКОРЕМ (reconcile.rs).
        let lines: Vec<String> =
            std::fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
        std::fs::write(&path, lines[..6].join("\n") + "\n").unwrap();
        let report = verify_chain(&path, true, false, None, 0, 0);
        assert!(report.valid);
        assert_eq!(report.records_checked, 6);
    }

    #[test]
    fn seq_gap_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.jsonl");
        {
            let mut w = ChainWriter::open(&path, ChainConfig::default(), signer()).unwrap();
            for i in 0..3 {
                w.append(format!("r{i}").as_bytes(), RecordKind::Prompt, "s", "u", None, None)
                    .unwrap();
            }
            w.sync_now().unwrap();
        }
        // удаляем СЕРЕДИНУ (не хвост) — seq gap + hash mismatch
        let lines: Vec<String> =
            std::fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
        let reduced = vec![lines[0].clone(), lines[2].clone()];
        std::fs::write(&path, reduced.join("\n") + "\n").unwrap();
        let report = verify_chain(&path, true, false, None, 0, 0);
        assert!(!report.valid);
        // разрыв обнаруживается на позиции пропущенной записи (seq 2 удалена)
        assert_eq!(report.first_bad_seq, 2);
    }

    #[test]
    fn nonce_cache_expires_after_window() {
        let mut cache = NonceCache::new(Duration::from_millis(50));
        let n = [1u8; 16];
        assert!(cache.check_and_insert(&n));
        assert!(!cache.check_and_insert(&n));
        std::thread::sleep(Duration::from_millis(80));
        assert!(cache.check_and_insert(&n), "после TTL nonce снова принимаем");
    }

    #[test]
    fn performance_nf03_group_commit() {
        // NF-03: >= 10 000 записей/с. В debug-сборке порог снижается
        // (крипто в debug в ~10 раз медленнее) — проверяется порядок величин.
        let dir = tempfile::tempdir().unwrap();
        let cfg = ChainConfig {
            sync_policy: SyncPolicy::GroupCommit { max_records: 5000, max_interval_ms: 10000 },
            ..Default::default()
        };
        let mut w = chain(&dir, cfg);
        let n = 10_000u64;
        let started = Instant::now();
        for i in 0..n {
            w.append(
                format!("payload-{i}").as_bytes(),
                RecordKind::Ipc,
                "bench",
                "d8",
                None,
                None,
            )
            .unwrap();
        }
        w.sync_now().unwrap();
        let elapsed = started.elapsed();
        let rate = n as f64 / elapsed.as_secs_f64();
        let threshold = if cfg!(debug_assertions) { 2_000.0 } else { 10_000.0 };
        assert!(
            rate >= threshold,
            "NF-03: {rate:.0} записей/с < порога {threshold:.0} (debug={})",
            cfg!(debug_assertions)
        );
    }
}
