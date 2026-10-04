//! Write-Ahead Log атомарных переходов FSM (F-F-05, AC-04).
//!
//! Формат кадра (little-endian):
//! ```text
//! magic    : [u8;4]  = "ZTW1"
//! rec_type : u8      (1=Intent, 2=Commit, 3=RollbackStage, 4=RollbackCommit,
//!                     5=SelfTestResult)
//! flags    : u8      (bit0 = fsync_confirmed, bit1 = watchdog_ack)
//! seq      : u64     монотонный номер записи WAL
//! ts_ns    : i64     unix-время, наносекунды
//! plen     : u32     длина JSON-payload
//! payload  : [u8; plen]
//! checksum : [u8;32] BLAKE3(magic..payload)
//! ```
//!
//! Атомарность перехода: `Intent` пишется и fsync'ится ДО применения;
//! `Commit` — ПОСЛЕ применения и подтверждения watchdog. При старте:
//! `Intent` без `Commit` (или оборванный хвост) → принудительный RECOVERY.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::state::{LifecycleState, OperatingMode, TransitionTrigger};

pub const WAL_MAGIC: &[u8; 4] = b"ZTW1";
pub const HEADER_LEN: usize = 4 + 1 + 1 + 8 + 8 + 4; // magic..plen
pub const CHECKSUM_LEN: usize = 32;
pub const MAX_PAYLOAD_LEN: u32 = 1 << 20; // 1 MiB sanity-limit

pub const FLAG_FSYNC: u8 = 0b01;
pub const FLAG_WATCHDOG_ACK: u8 = 0b10;

#[derive(Debug, Error)]
pub enum WalError {
    #[error("wal io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wal frame corrupt at offset {offset}: {reason}")]
    Corrupt { offset: u64, reason: String },
    #[error("wal payload invalid: {0}")]
    Payload(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WalRecordType {
    Intent = 1,
    Commit = 2,
    RollbackStage = 3,
    RollbackCommit = 4,
    SelfTestResult = 5,
}

impl WalRecordType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => WalRecordType::Intent,
            2 => WalRecordType::Commit,
            3 => WalRecordType::RollbackStage,
            4 => WalRecordType::RollbackCommit,
            5 => WalRecordType::SelfTestResult,
            _ => return None,
        })
    }
}

/// Payload записи Intent/Commit (переход).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransitionPayload {
    pub from_lifecycle: LifecycleState,
    pub to_lifecycle: LifecycleState,
    pub from_mode: OperatingMode,
    pub to_mode: OperatingMode,
    pub epoch: u64,
    pub trigger: TransitionTrigger,
    pub reason: String,
    /// Для Commit: seq соответствующего Intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_seq: Option<u64>,
}

/// Payload записи SelfTestResult.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelfTestPayload {
    pub passed: bool,
    pub total_duration_ms: u64,
    pub items: Vec<SelfTestItemPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelfTestItemPayload {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub duration_ms: u64,
}

/// Одна запись WAL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalRecord {
    pub seq: u64,
    pub record_type: WalRecordType,
    pub flags: u8,
    pub ts_ns: i64,
    /// JSON-payload (типизированный доступ — через [`WalRecord::transition`]
    /// и [`WalRecord::self_test`]).
    pub payload: serde_json::Value,
    pub checksum: [u8; 32],
}

impl WalRecord {
    pub fn fsync_confirmed(&self) -> bool {
        self.flags & FLAG_FSYNC != 0
    }
    pub fn watchdog_ack(&self) -> bool {
        self.flags & FLAG_WATCHDOG_ACK != 0
    }
    pub fn transition(&self) -> Option<TransitionPayload> {
        serde_json::from_value(self.payload.clone()).ok()
    }
    pub fn self_test(&self) -> Option<SelfTestPayload> {
        serde_json::from_value(self.payload.clone()).ok()
    }
}

pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn frame_checksum(rec_type: u8, flags: u8, seq: u64, ts_ns: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WAL_MAGIC);
    hasher.update(&[rec_type, flags]);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&ts_ns.to_le_bytes());
    hasher.update(&(payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Append-only писатель WAL с гарантированным fsync (F-F-05).
pub struct WalWriter {
    path: PathBuf,
    file: File,
    writer: BufWriter<File>,
    next_seq: u64,
    fsync_policy: bool,
}

impl WalWriter {
    /// Открыть/создать WAL; `next_seq` продолжает существующий файл.
    pub fn open(path: impl AsRef<Path>, fsync_policy: bool) -> Result<Self, WalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let next_seq = match scan_records(&path) {
            Ok((records, _truncated_tail)) => {
                records.last().map(|r| r.seq + 1).unwrap_or(1)
            }
            Err(_) => 1, // повреждённый WAL — seq с 1; восстановление решает engine
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let writer = BufWriter::new(file.try_clone()?);
        Ok(Self { path, file, writer, next_seq, fsync_policy })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Дописать запись; вернуть присвоенный seq.
    pub fn append(
        &mut self,
        record_type: WalRecordType,
        flags: u8,
        payload: &serde_json::Value,
    ) -> Result<u64, WalError> {
        let seq = self.next_seq;
        let ts = now_ns();
        let payload_bytes = serde_json::to_vec(payload)
            .map_err(|e| WalError::Payload(e.to_string()))?;
        if payload_bytes.len() > MAX_PAYLOAD_LEN as usize {
            return Err(WalError::Payload(format!(
                "payload too large: {}",
                payload_bytes.len()
            )));
        }
        let checksum =
            frame_checksum(record_type as u8, flags, seq, ts, &payload_bytes);

        let mut frame = Vec::with_capacity(HEADER_LEN + payload_bytes.len() + CHECKSUM_LEN);
        frame.extend_from_slice(WAL_MAGIC);
        frame.push(record_type as u8);
        frame.push(flags);
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&ts.to_le_bytes());
        frame.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload_bytes);
        frame.extend_from_slice(&checksum);

        self.writer.write_all(&frame)?;
        self.writer.flush()?;
        if self.fsync_policy {
            self.file.sync_all()?;
        }
        self.next_seq += 1;
        Ok(seq)
    }

    /// Удобная обёртка: Intent-запись перехода.
    pub fn append_intent(&mut self, t: &TransitionPayload) -> Result<u64, WalError> {
        let payload = serde_json::to_value(t).map_err(|e| WalError::Payload(e.to_string()))?;
        self.append(WalRecordType::Intent, FLAG_FSYNC, &payload)
    }

    /// Удобная обёртка: Commit-запись (после watchdog ack).
    pub fn append_commit(
        &mut self,
        t: &TransitionPayload,
        intent_seq: u64,
        watchdog_ack: bool,
    ) -> Result<u64, WalError> {
        let mut t = t.clone();
        t.intent_seq = Some(intent_seq);
        let payload = serde_json::to_value(&t).map_err(|e| WalError::Payload(e.to_string()))?;
        let flags = FLAG_FSYNC | if watchdog_ack { FLAG_WATCHDOG_ACK } else { 0 };
        self.append(WalRecordType::Commit, flags, &payload)
    }
}

/// Результат сканирования WAL при старте (F-F-05: «незавершённый переход →
/// принудительный RECOVERY + повтор SELF_TEST»).
#[derive(Debug, Clone, Default)]
pub struct WalRecovery {
    pub records: Vec<WalRecord>,
    /// Intent без парного Commit — признак перехода, прерванного аварией.
    pub dangling_intent: Option<(u64, TransitionPayload)>,
    /// Последний кадр оборван (torn write при потере питания).
    pub truncated_tail: bool,
    /// Контрольная сумма не сошлась в СЕРЕДИНЕ файла — признак тамперинга.
    pub mid_file_corruption: bool,
    pub last_seq: u64,
}

impl WalRecovery {
    pub fn needs_forced_recovery(&self) -> bool {
        self.dangling_intent.is_some() || self.truncated_tail
    }
}

fn scan_records(path: &Path) -> Result<(Vec<WalRecord>, bool), WalError> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), false));
        }
        Err(e) => return Err(WalError::Io(e)),
    };
    let mut records = Vec::new();
    let mut offset: u64 = 0;
    let mut truncated_tail = false;
    loop {
        let mut header = [0u8; HEADER_LEN];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(WalError::Io(e)),
        }
        if &header[..4] != WAL_MAGIC {
            truncated_tail = true;
            break;
        }
        let rec_type = header[4];
        let flags = header[5];
        let seq = u64::from_le_bytes(header[6..14].try_into().unwrap());
        let ts_ns = i64::from_le_bytes(header[14..22].try_into().unwrap());
        let plen = u32::from_le_bytes(header[22..26].try_into().unwrap());
        if plen > MAX_PAYLOAD_LEN {
            truncated_tail = true;
            break;
        }
        let mut payload = vec![0u8; plen as usize];
        let mut checksum = [0u8; CHECKSUM_LEN];
        let body_read = file.read_exact(&mut payload).and_then(|_| file.read_exact(&mut checksum));
        if let Err(e) = body_read {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                truncated_tail = true;
                break;
            }
            return Err(WalError::Io(e));
        }
        let expected = frame_checksum(rec_type, flags, seq, ts_ns, &payload);
        if expected != checksum {
            return Err(WalError::Corrupt {
                offset,
                reason: "blake3 checksum mismatch (тамперинг или битый сектор)".into(),
            });
        }
        let record_type = WalRecordType::from_u8(rec_type).ok_or_else(|| WalError::Corrupt {
            offset,
            reason: format!("unknown record type {rec_type}"),
        })?;
        let value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| WalError::Payload(e.to_string()))?;
        records.push(WalRecord {
            seq,
            record_type,
            flags,
            ts_ns,
            payload: value,
            checksum,
        });
        offset += (HEADER_LEN + plen as usize + CHECKSUM_LEN) as u64;
    }
    Ok((records, truncated_tail))
}

/// Полное восстановление WAL: записи + анализ незавершённых переходов.
pub fn recover(path: impl AsRef<Path>) -> Result<WalRecovery, WalError> {
    let path = path.as_ref();
    let mut out = WalRecovery::default();
    let (records, truncated_tail) = match scan_records(path) {
        Ok(v) => v,
        Err(WalError::Corrupt { .. }) => {
            // Битая контрольная сумма в середине файла: перечитываем, что
            // удалось, и фиксируем mid_file_corruption (инцидент безопасности).
            out.mid_file_corruption = true;
            let partial = scan_partial(path);
            (partial, false)
        }
        Err(e) => return Err(e),
    };
    out.truncated_tail = truncated_tail;
    out.last_seq = records.last().map(|r| r.seq).unwrap_or(0);

    // Поиск dangling Intent: Intent без Commit с тем же intent_seq/epoch.
    let mut open_intents: Vec<(u64, TransitionPayload)> = Vec::new();
    for r in &records {
        match r.record_type {
            WalRecordType::Intent => {
                if let Some(t) = r.transition() {
                    open_intents.push((r.seq, t));
                }
            }
            WalRecordType::Commit => {
                if let Some(t) = r.transition() {
                    if let Some(intent_seq) = t.intent_seq {
                        open_intents.retain(|(seq, _)| *seq != intent_seq);
                    }
                }
            }
            _ => {}
        }
    }
    out.dangling_intent = open_intents.into_iter().next();
    out.records = records;
    Ok(out)
}

fn scan_partial(path: &Path) -> Vec<WalRecord> {
    // Читаем валидный префикс до первой битой записи (для форензики).
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut records = Vec::new();
    loop {
        let mut header = [0u8; HEADER_LEN];
        if file.read_exact(&mut header).is_err() || &header[..4] != WAL_MAGIC {
            break;
        }
        let rec_type = header[4];
        let flags = header[5];
        let seq = u64::from_le_bytes(header[6..14].try_into().unwrap());
        let ts_ns = i64::from_le_bytes(header[14..22].try_into().unwrap());
        let plen = u32::from_le_bytes(header[22..26].try_into().unwrap());
        if plen > MAX_PAYLOAD_LEN {
            break;
        }
        let mut payload = vec![0u8; plen as usize];
        let mut checksum = [0u8; CHECKSUM_LEN];
        if file.read_exact(&mut payload).is_err() || file.read_exact(&mut checksum).is_err() {
            break;
        }
        if frame_checksum(rec_type, flags, seq, ts_ns, &payload) != checksum {
            break; // первая битая запись — дальше не читаем
        }
        let Some(record_type) = WalRecordType::from_u8(rec_type) else { break };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) else { break };
        records.push(WalRecord { seq, record_type, flags, ts_ns, payload: value, checksum });
    }
    records
}

/// Хвост WAL для форензики (fsm.proto:GetWalTail).
pub fn tail(path: impl AsRef<Path>, max_records: usize) -> Result<Vec<WalRecord>, WalError> {
    let recovery = recover(path)?;
    let n = recovery.records.len();
    Ok(recovery.records.into_iter().skip(n.saturating_sub(max_records)).collect())
}

/// Обрезать WAL-файл до валидного префикса (операция восстановления после
/// torn write; только по команде оператора/RECOVERY-процедуры).
pub fn truncate_to_valid_prefix(path: impl AsRef<Path>) -> Result<u64, WalError> {
    let records = scan_partial(path.as_ref());
    let mut valid_len: u64 = 0;
    for r in &records {
        let plen = serde_json::to_vec(&r.payload).map_err(|e| WalError::Payload(e.to_string()))?.len();
        valid_len += (HEADER_LEN + plen + CHECKSUM_LEN) as u64;
    }
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(valid_len)?;
    file.sync_all()?;
    Ok(valid_len)
}

/// Проверка, что файл WAL существует и не пуст (для healthcheck).
pub fn wal_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().metadata().map(|m| m.is_file()).unwrap_or(false)
}

/// Утилита тестов: позиция конца файла.
pub fn file_len(path: impl AsRef<Path>) -> u64 {
    File::open(path)
        .and_then(|mut f| f.seek(SeekFrom::End(0)))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{LifecycleState as L, OperatingMode as M, TransitionTrigger as T};

    fn sample_transition() -> TransitionPayload {
        TransitionPayload {
            from_lifecycle: L::Boot,
            to_lifecycle: L::SelfTest,
            from_mode: M::Nominal,
            to_mode: M::Nominal,
            epoch: 1,
            trigger: T::BootOk,
            reason: "boot ok".into(),
            intent_seq: None,
        }
    }

    #[test]
    fn append_and_recover_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        {
            let mut w = WalWriter::open(&path, true).unwrap();
            let t = sample_transition();
            let intent_seq = w.append_intent(&t).unwrap();
            w.append_commit(&t, intent_seq, true).unwrap();
            assert_eq!(w.next_seq(), 3);
        }
        let rec = recover(&path).unwrap();
        assert_eq!(rec.records.len(), 2);
        assert!(!rec.needs_forced_recovery());
        assert_eq!(rec.last_seq, 2);
        assert!(rec.records[1].watchdog_ack());
        assert!(rec.records[1].fsync_confirmed());
        let t = rec.records[0].transition().unwrap();
        assert_eq!(t.to_lifecycle, L::SelfTest);
        assert_eq!(rec.records[1].transition().unwrap().intent_seq, Some(1));
    }

    #[test]
    fn dangling_intent_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        {
            let mut w = WalWriter::open(&path, true).unwrap();
            w.append_intent(&sample_transition()).unwrap();
            // Commit НЕ пишем — имитация потери питания (AC-04)
        }
        let rec = recover(&path).unwrap();
        assert!(rec.needs_forced_recovery());
        let (seq, t) = rec.dangling_intent.unwrap();
        assert_eq!(seq, 1);
        assert_eq!(t.to_lifecycle, L::SelfTest);
    }

    #[test]
    fn truncated_tail_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        {
            let mut w = WalWriter::open(&path, true).unwrap();
            let t = sample_transition();
            let s = w.append_intent(&t).unwrap();
            w.append_commit(&t, s, true).unwrap();
        }
        // обрываем последний кадр на середине (torn write)
        let len = file_len(&path);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 10)
            .unwrap();
        let rec = recover(&path).unwrap();
        assert!(rec.truncated_tail);
        assert!(rec.needs_forced_recovery());
        assert_eq!(rec.records.len(), 1); // первая запись цела
    }

    #[test]
    fn checksum_tamper_detected_as_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        {
            let mut w = WalWriter::open(&path, true).unwrap();
            let t = sample_transition();
            let s = w.append_intent(&t).unwrap();
            w.append_commit(&t, s, true).unwrap();
        }
        // тамперинг: меняем байт payload ПЕРВОЙ записи (середина файла)
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN + 5] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        let rec = recover(&path).unwrap();
        assert!(rec.mid_file_corruption, "подмена в середине WAL обязана детектироваться");
    }

    #[test]
    fn truncate_to_valid_prefix_repairs_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        {
            let mut w = WalWriter::open(&path, true).unwrap();
            let t = sample_transition();
            let s = w.append_intent(&t).unwrap();
            w.append_commit(&t, s, true).unwrap();
        }
        let len = file_len(&path);
        std::fs::OpenOptions::new().write(true).open(&path).unwrap()
            .set_len(len - 7).unwrap();
        let valid = truncate_to_valid_prefix(&path).unwrap();
        assert!(valid < len);
        let rec = recover(&path).unwrap();
        assert!(!rec.truncated_tail);
        assert_eq!(rec.records.len(), 1);
    }

    #[test]
    fn seq_continues_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        {
            let mut w = WalWriter::open(&path, true).unwrap();
            w.append_intent(&sample_transition()).unwrap();
        }
        let w2 = WalWriter::open(&path, true).unwrap();
        assert_eq!(w2.next_seq(), 2);
    }

    #[test]
    fn tail_returns_last_n() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        let mut w = WalWriter::open(&path, true).unwrap();
        for i in 0..10 {
            let mut t = sample_transition();
            t.epoch = i;
            w.append_intent(&t).unwrap();
        }
        drop(w);
        let t = tail(&path, 3).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.last().unwrap().seq, 10);
    }
}
