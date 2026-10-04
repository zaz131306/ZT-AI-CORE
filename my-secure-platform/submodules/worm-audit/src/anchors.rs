//! Dual-anchor якорение чекпоинтов (F-G-04/05):
//!   1. TPM NV-Counter — offline-верификация, ≤ 1 записи/час, учёт износа;
//!   2. Внешний WORM-сервис (S3 Object Lock / отдельный узел) — каждый чекпоинт.
//!
//! [`DirectoryAnchor`] — файловая реализация внешнего якоря для dev/CI
//! (запись + chmod a-w, имитация Object Lock). Прод: S3-адаптер реализует
//! тот же трейд [`ExternalAnchor`] (PUT в bucket с Object Lock Compliance).
//! При недоступности внешнего якоря > 5 мин чекпоинты копятся в
//! [`LocalCheckpointBuffer`] (защищённый локальный буфер, F-G-04).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use thiserror::Error;
use zt_hal_common::tpm::{TpmError, TpmOps};

use crate::checkpoint::Checkpoint;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("anchor unavailable: {0}")]
    Unavailable(String),
    #[error("anchor rate-limited: TPM NV запись не чаще 1 раза в час (F-G-05)")]
    RateLimited,
    #[error("anchor io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tpm: {0}")]
    Tpm(#[from] TpmError),
}

/// Якорь №1: TPM NV-Counter (F-G-04 п.1, F-G-05).
pub struct TpmAnchor<T: TpmOps> {
    tpm: T,
    nv_index: u32,
    min_interval: Duration,
    last_write: Option<Instant>,
    pub wear_alert_threshold: f64,
    pub wear_alerted: bool,
}

impl<T: TpmOps> TpmAnchor<T> {
    pub fn new(tpm: T, nv_index: u32) -> Self {
        Self {
            tpm,
            nv_index,
            min_interval: Duration::from_secs(3600), // ≤ 1 записи/час (F-G-05)
            last_write: None,
            wear_alert_threshold: 80.0,
            wear_alerted: false,
        }
    }

    /// Dev/тесты: сократить интервал rate-limit.
    pub fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_interval = interval;
        self
    }

    /// Заякорить чекпоинт. `Ok(false)` — пропуск из-за rate-limit
    /// (чекпоинт уходит только в S3, F-G-05).
    pub fn publish(&mut self, cp: &Checkpoint) -> Result<bool, AnchorError> {
        if !self.tpm.available() {
            return Err(AnchorError::Unavailable("TPM offline".into()));
        }
        if let Some(last) = self.last_write {
            if last.elapsed() < self.min_interval {
                return Ok(false); // rate-limit: только S3
            }
        }
        // NV-счётчик монотонен: значение = last_seq чекпоинта.
        self.tpm.nv_write_monotonic(self.nv_index, cp.last_seq)?;
        self.last_write = Some(Instant::now());
        // Износ NV-ячейки (F-G-05): ≥ 80% → алерт (флаг читает сервер/FSM).
        let wear = self.tpm.nv_wear_percent(self.nv_index)?;
        if wear >= self.wear_alert_threshold && !self.wear_alerted {
            self.wear_alerted = true;
            eprintln!(
                "[worm-audit] ALERT: TPM NV wear {wear:.1}% ≥ {:.0}% → DEGRADED (F-G-05)",
                self.wear_alert_threshold
            );
        }
        Ok(true)
    }

    /// Последняя заякоренная последовательность (для сверки при старте).
    pub fn latest_seq(&mut self) -> Result<u64, AnchorError> {
        Ok(self.tpm.nv_read(self.nv_index)?)
    }

    pub fn wear_percent(&mut self) -> Result<f64, AnchorError> {
        Ok(self.tpm.nv_wear_percent(self.nv_index)?)
    }

    pub fn available(&self) -> bool {
        self.tpm.available()
    }

    pub fn last_write(&self) -> Option<Instant> {
        self.last_write
    }
}

/// Якорь №2: внешний WORM-сервис (F-G-04 п.2).
pub trait ExternalAnchor {
    /// Опубликовать чекпоинт (S3 PUT c Object Lock / запись на узел).
    fn publish(&mut self, cp: &Checkpoint) -> Result<(), AnchorError>;
    /// Последняя подтверждённая последовательность.
    fn latest_seq(&mut self) -> Result<u64, AnchorError>;
    fn available(&self) -> bool;
}

/// Файловый внешний якорь (dev/CI; эмуляция S3 Object Lock: после записи
/// файл переводится в read-only).
pub struct DirectoryAnchor {
    dir: PathBuf,
    online: bool,
}

impl DirectoryAnchor {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, AnchorError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, online: true })
    }

    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }

    fn cp_path(&self, last_seq: u64) -> PathBuf {
        self.dir.join(format!("checkpoint-{last_seq:020}.json"))
    }
}

impl ExternalAnchor for DirectoryAnchor {
    fn publish(&mut self, cp: &Checkpoint) -> Result<(), AnchorError> {
        if !self.online {
            return Err(AnchorError::Unavailable("external anchor offline (S3 503)".into()));
        }
        let path = self.cp_path(cp.last_seq);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(serde_json::to_vec_pretty(cp).unwrap().as_slice())?;
        file.sync_all()?;
        drop(file);
        // Object Lock (Compliance mode): объект становится неизменяемым.
        lock_readonly(&path);
        Ok(())
    }

    fn latest_seq(&mut self) -> Result<u64, AnchorError> {
        if !self.online {
            return Err(AnchorError::Unavailable("external anchor offline".into()));
        }
        let mut max_seq = 0u64;
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name().to_string_lossy().to_string();
            if let Some(rest) = name.strip_prefix("checkpoint-") {
                if let Some(digits) = rest.strip_suffix(".json") {
                    if let Ok(seq) = digits.parse::<u64>() {
                        max_seq = max_seq.max(seq);
                    }
                }
            }
        }
        Ok(max_seq)
    }

    fn available(&self) -> bool {
        self.online
    }
}

#[cfg(unix)]
fn lock_readonly(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444));
}

#[cfg(not(unix))]
fn lock_readonly(_path: &Path) {}

/// Якорь, который всегда падает (chaos-тесты: сценарий D — S3 503).
pub struct FailingAnchor {
    pub seq_before_failure: u64,
    online: bool,
}

impl FailingAnchor {
    pub fn new() -> Self {
        Self { seq_before_failure: 0, online: false }
    }
}

impl Default for FailingAnchor {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalAnchor for FailingAnchor {
    fn publish(&mut self, _cp: &Checkpoint) -> Result<(), AnchorError> {
        Err(AnchorError::Unavailable("HTTP 503 (chaos scenario D)".into()))
    }
    fn latest_seq(&mut self) -> Result<u64, AnchorError> {
        if self.online {
            Ok(self.seq_before_failure)
        } else {
            Err(AnchorError::Unavailable("HTTP 503 (chaos scenario D)".into()))
        }
    }
    fn available(&self) -> bool {
        self.online
    }
}

/// Локальный защищённый буфер чекпоинтов при недоступном внешнем якоре
/// (F-G-04: «чекпоинты копятся в локальном защищённом буфере»).
pub struct LocalCheckpointBuffer {
    dir: PathBuf,
}

impl LocalCheckpointBuffer {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, AnchorError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn push(&self, cp: &Checkpoint) -> Result<(), AnchorError> {
        let path = self.dir.join(format!("buffered-{:020}.json", cp.last_seq));
        let mut f = File::create(&path)?;
        f.write_all(serde_json::to_vec(cp).unwrap().as_slice())?;
        f.sync_all()?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        std::fs::read_dir(&self.dir)
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Слить буфер во внешний якорь после восстановления (runbook §5).
    pub fn flush_to<A: ExternalAnchor>(&self, anchor: &mut A) -> Result<usize, AnchorError> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        let mut flushed = 0;
        for path in entries {
            let text = std::fs::read_to_string(&path)?;
            let cp: Checkpoint = serde_json::from_str(&text)
                .map_err(|e| AnchorError::Unavailable(e.to_string()))?;
            anchor.publish(&cp)?;
            std::fs::remove_file(&path)?;
            flushed += 1;
        }
        Ok(flushed)
    }
}

/// Сводное состояние якорей (audit.proto:AnchorStatus).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchorStatus {
    pub seq_tpm: u64,
    pub seq_ext: u64,
    pub tpm_last_write_unix_ns: i64,
    pub tpm_nv_wear_percent: f64,
    pub tpm_available: bool,
    pub ext_available: bool,
    pub ext_last_ok_unix_ns: i64,
    pub buffered_checkpoints: usize,
}

impl Default for AnchorStatus {
    fn default() -> Self {
        Self {
            seq_tpm: 0,
            seq_ext: 0,
            tpm_last_write_unix_ns: 0,
            tpm_nv_wear_percent: 0.0,
            tpm_available: false,
            ext_available: false,
            ext_last_ok_unix_ns: 0,
            buffered_checkpoints: 0,
        }
    }
}

/// Хронометраж доступности внешнего якоря (порог 5 минут — F-G-04).
pub struct ExtAvailabilityTracker {
    down_since: Option<Instant>,
    pub threshold: Duration,
    pub last_ok: Option<SystemTime>,
}

impl ExtAvailabilityTracker {
    pub fn new() -> Self {
        Self {
            down_since: None,
            threshold: Duration::from_secs(300),
            last_ok: None,
        }
    }

    pub fn mark_ok(&mut self) {
        self.down_since = None;
        self.last_ok = Some(SystemTime::now());
    }

    pub fn mark_failure(&mut self) {
        if self.down_since.is_none() {
            self.down_since = Some(Instant::now());
        }
    }

    /// Якорь недоступен дольше порога → DEGRADED (F-G-04).
    pub fn degraded(&self) -> bool {
        self.down_since
            .map(|t| t.elapsed() >= self.threshold)
            .unwrap_or(false)
    }

    pub fn down_for(&self) -> Option<Duration> {
        self.down_since.map(|t| t.elapsed())
    }
}

impl Default for ExtAvailabilityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::SeedSigner;
    use crate::checkpoint::create_checkpoint;
    use zt_hal_common::tpm::MockTpm;

    fn cp(last_seq: u64) -> Checkpoint {
        let s = SeedSigner::from_seed(*b"zt-worm-anchor-test-seed-0000001");
        create_checkpoint(last_seq.saturating_sub(9), last_seq, &[1u8; 32], &s)
    }

    #[test]
    fn tpm_anchor_publishes_and_rate_limits() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        let mut anchor = TpmAnchor::new(tpm, 0x0150_0001);
        // первая запись проходит
        assert!(anchor.publish(&cp(100)).unwrap());
        assert_eq!(anchor.latest_seq().unwrap(), 100);
        // вторая в пределах часа — rate-limit (F-G-05: только S3)
        assert!(!anchor.publish(&cp(200)).unwrap());
        assert_eq!(anchor.latest_seq().unwrap(), 100);
    }

    #[test]
    fn tpm_anchor_rate_limit_shortened_for_tests() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        let mut anchor = TpmAnchor::new(tpm, 1).with_min_interval(Duration::from_millis(50));
        assert!(anchor.publish(&cp(10)).unwrap());
        assert!(!anchor.publish(&cp(20)).unwrap());
        std::thread::sleep(Duration::from_millis(80));
        assert!(anchor.publish(&cp(20)).unwrap());
        assert_eq!(anchor.latest_seq().unwrap(), 20);
    }

    #[test]
    fn tpm_nv_wear_alert_at_80_percent() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        // endurance mock = 100 записей → 80 записей = 80%
        let mut anchor = TpmAnchor::new(tpm, 2).with_min_interval(Duration::ZERO);
        for i in 1..=80u64 {
            anchor.publish(&cp(i)).unwrap();
        }
        let wear = anchor.wear_percent().unwrap();
        assert!((wear - 80.0).abs() < 0.5, "wear={wear}");
        assert!(anchor.wear_alerted, "алерт износа NV обязан взвестись при 80%");
    }

    #[test]
    fn tpm_anchor_unavailable_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let mut tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        tpm.set_online(false);
        let mut anchor = TpmAnchor::new(tpm, 3);
        assert!(matches!(anchor.publish(&cp(1)), Err(AnchorError::Unavailable(_))));
        assert!(!anchor.available());
    }

    #[test]
    fn directory_anchor_publish_and_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut anchor = DirectoryAnchor::new(dir.path().join("ext")).unwrap();
        anchor.publish(&cp(500)).unwrap();
        assert_eq!(anchor.latest_seq().unwrap(), 500);
        anchor.publish(&cp(700)).unwrap();
        assert_eq!(anchor.latest_seq().unwrap(), 700);
        // Object Lock: файл read-only
        let f = dir.path().join("ext/checkpoint-00000000000000000700.json");
        let md = std::fs::metadata(&f).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(md.permissions().mode() & 0o222, 0, "объект обязан быть неизменяемым");
    }

    #[test]
    fn directory_anchor_offline() {
        let dir = tempfile::tempdir().unwrap();
        let mut anchor = DirectoryAnchor::new(dir.path().join("ext")).unwrap();
        anchor.set_online(false);
        assert!(matches!(anchor.publish(&cp(1)), Err(AnchorError::Unavailable(_))));
        assert!(!anchor.available());
    }

    #[test]
    fn buffer_accumulates_and_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = LocalCheckpointBuffer::new(dir.path().join("buf")).unwrap();
        let mut ext = DirectoryAnchor::new(dir.path().join("ext")).unwrap();
        ext.set_online(false);
        // S3 недоступен → чекпоинты в буфер (F-G-04)
        for seq in [10u64, 20, 30] {
            let cp = cp(seq);
            assert!(ext.publish(&cp).is_err());
            buffer.push(&cp).unwrap();
        }
        assert_eq!(buffer.len(), 3);
        // восстановление → слив
        ext.set_online(true);
        let flushed = buffer.flush_to(&mut ext).unwrap();
        assert_eq!(flushed, 3);
        assert_eq!(buffer.len(), 0);
        assert_eq!(ext.latest_seq().unwrap(), 30);
    }

    #[test]
    fn ext_tracker_threshold() {
        let mut t = ExtAvailabilityTracker::new();
        t.threshold = Duration::from_millis(50);
        assert!(!t.degraded());
        t.mark_failure();
        assert!(!t.degraded());
        std::thread::sleep(Duration::from_millis(80));
        assert!(t.degraded(), "> 5 мин (здесь 50 мс) недоступен → DEGRADED");
        t.mark_ok();
        assert!(!t.degraded());
        assert!(t.last_ok.is_some());
    }

    #[test]
    fn failing_anchor_is_always_down() {
        let mut a = FailingAnchor::new();
        assert!(a.publish(&cp(1)).is_err());
        assert!(a.latest_seq().is_err());
        assert!(!a.available());
    }
}
