//! [`AuditService`] — оркестрация: цепочка + планировщик чекпоинтов +
//! dual-anchor + сверка при старте + ingestion спулов (bootstrap/egress).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;
use zt_hal_common::tpm::TpmOps;

use crate::anchors::{
    AnchorStatus, ExtAvailabilityTracker, ExternalAnchor, LocalCheckpointBuffer, TpmAnchor,
};
use crate::chain::{ChainConfig, ChainError, ChainSigner, ChainStats, ChainWriter, VerifyReport};
use crate::checkpoint::{create_checkpoint, Checkpoint, CheckpointPolicy, CheckpointScheduler};
use crate::record::{AuditRecord, RecordKind};
use crate::reconcile::{reconcile, ReconcileInput, ReconcileReport, ReconcileVerdict};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("anchor: {0}")]
    Anchor(#[from] crate::anchors::AnchorError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(String),
}

/// Конфигурация сервиса.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub chain: ChainConfig,
    pub checkpoint_policy: CheckpointPolicy,
    /// Индекс TPM NV-Counter для якоря WORM.
    pub tpm_nv_index: u32,
    /// Лимит записи в TPM NV (F-G-05: не чаще 1 раза в час).
    pub tpm_min_interval: Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            chain: ChainConfig::default(),
            checkpoint_policy: CheckpointPolicy::default(),
            tpm_nv_index: 0x0150_0001,
            tpm_min_interval: Duration::from_secs(3600),
        }
    }
}

/// Результат публикации чекпоинта (audit.proto:PublishCheckpointResponse).
#[derive(Debug, Clone, Serialize)]
pub struct PublishOutcome {
    pub published: bool,
    pub checkpoint: Option<Checkpoint>,
    pub tpm_anchored: bool,
    pub ext_anchored: bool,
    pub buffered: bool,
    pub detail: String,
}

/// WORM-сервис: цепочка, чекпоинты, dual-anchor, сверка.
pub struct AuditService<T: TpmOps, E: ExternalAnchor> {
    chain: ChainWriter,
    scheduler: CheckpointScheduler,
    tpm_anchor: TpmAnchor<T>,
    ext_anchor: E,
    ext_tracker: ExtAvailabilityTracker,
    buffer: LocalCheckpointBuffer,
    checkpoints_path: PathBuf,
    last_checkpoint: Option<Checkpoint>,
    config: ServiceConfig,
}

impl<T: TpmOps, E: ExternalAnchor> AuditService<T, E> {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        chain_path: impl AsRef<Path>,
        checkpoints_path: impl AsRef<Path>,
        buffer_dir: impl AsRef<Path>,
        tpm: T,
        ext_anchor: E,
        signer: Box<dyn ChainSigner>,
        config: ServiceConfig,
    ) -> Result<Self, ServiceError> {
        let current_seq = crate::chain::peek_next_seq(chain_path.as_ref())?;
        let chain = ChainWriter::open(chain_path.as_ref(), config.chain.clone(), signer)?;
        let checkpoints_path = checkpoints_path.as_ref().to_path_buf();
        if let Some(parent) = checkpoints_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let last_checkpoint = read_last_checkpoint(&checkpoints_path)?;
        let base_seq = last_checkpoint
            .as_ref()
            .map(|c| c.last_seq)
            .unwrap_or(current_seq.saturating_sub(1));
        let scheduler = CheckpointScheduler::new(config.checkpoint_policy.clone(), base_seq);
        let tpm_anchor = TpmAnchor::new(tpm, config.tpm_nv_index)
            .with_min_interval(config.tpm_min_interval);
        let buffer = LocalCheckpointBuffer::new(buffer_dir)?;
        Ok(Self {
            chain,
            scheduler,
            tpm_anchor,
            ext_anchor,
            ext_tracker: ExtAvailabilityTracker::new(),
            buffer,
            checkpoints_path,
            last_checkpoint,
            config,
        })
    }

    // --- запись ---------------------------------------------------------------

    /// Append + автопубликация чекпоинта по политике (F-G-04).
    pub fn append(
        &mut self,
        payload: &[u8],
        kind: RecordKind,
        source: &str,
        subject: &str,
    ) -> Result<AuditRecord, ServiceError> {
        let record = self.chain.append(payload, kind, source, subject, None, None)?;
        let seq_now = self.chain.seq().saturating_sub(1);
        if self.scheduler.is_due(seq_now) {
            let _ = self.publish_checkpoint(false, true, true);
        }
        Ok(record)
    }

    // --- чекпоинты --------------------------------------------------------------

    /// Опубликовать чекпоинт (force — игнорировать пороги; runbook §2).
    pub fn publish_checkpoint(
        &mut self,
        force: bool,
        anchor_tpm: bool,
        anchor_ext: bool,
    ) -> Result<PublishOutcome, ServiceError> {
        let last_seq = self.chain.seq().saturating_sub(1);
        let first_seq = self
            .last_checkpoint
            .as_ref()
            .map(|c| c.last_seq + 1)
            .unwrap_or(1);
        if last_seq == 0 {
            return Ok(PublishOutcome {
                published: false,
                checkpoint: None,
                tpm_anchored: false,
                ext_anchored: false,
                buffered: false,
                detail: "цепочка пуста — публиковать нечего".into(),
            });
        }
        if !force && !self.scheduler.is_due(last_seq) {
            return Ok(PublishOutcome {
                published: false,
                checkpoint: None,
                tpm_anchored: false,
                ext_anchored: false,
                buffered: false,
                detail: format!(
                    "порог не достигнут (records_since={}, elapsed={:?})",
                    self.scheduler.records_since(last_seq),
                    self.scheduler.elapsed()
                ),
            });
        }
        // fsync хвоста перед якорением — чекпоинт обязан покрывать только
        // гарантированно сохранённые записи.
        self.chain.sync_now()?;
        let cp = create_checkpoint(first_seq, last_seq, &self.chain.head(), self.chain.signer());

        // Якорь 2: внешний WORM (S3 Object Lock) — при каждом чекпоинте.
        let mut ext_anchored = false;
        let mut buffered = false;
        if anchor_ext {
            match self.ext_anchor.publish(&cp) {
                Ok(()) => {
                    self.ext_tracker.mark_ok();
                    ext_anchored = true;
                    // восстановление после простоя: сливаем локальный буфер
                    if !self.buffer.is_empty() {
                        match self.buffer.flush_to(&mut self.ext_anchor) {
                            Ok(n) => eprintln!(
                                "[worm-audit] буфер чекпоинтов слит во внешний якорь: {n}"
                            ),
                            Err(e) => eprintln!("[worm-audit] WARN: flush buffer: {e}"),
                        }
                    }
                }
                Err(e) => {
                    self.ext_tracker.mark_failure();
                    // F-G-04: чекпоинты копятся в локальном защищённом буфере
                    self.buffer.push(&cp)?;
                    buffered = true;
                    eprintln!("[worm-audit] WARN: external anchor failed: {e} (буферизовано)");
                }
            }
        }

        // Якорь 1: TPM NV-Counter — не чаще 1 раза в час (F-G-05).
        let mut tpm_anchored = false;
        if anchor_tpm {
            match self.tpm_anchor.publish(&cp) {
                Ok(true) => tpm_anchored = true,
                Ok(false) => {} // rate-limit: чекпоинт только в S3 — штатно
                Err(e) => eprintln!("[worm-audit] WARN: TPM anchor failed: {e} (chaos C: только S3)"),
            }
        }

        // Локальный журнал чекпоинтов (append-only JSONL).
        append_checkpoint_file(&self.checkpoints_path, &cp)?;
        self.scheduler.mark_published(last_seq);
        self.last_checkpoint = Some(cp.clone());

        let detail = if self.ext_tracker.degraded() {
            "внешний якорь недоступен > 5 мин → FSM DEGRADED (F-G-04)".to_string()
        } else {
            String::new()
        };
        Ok(PublishOutcome {
            published: true,
            checkpoint: Some(cp),
            tpm_anchored,
            ext_anchored,
            buffered,
            detail,
        })
    }

    // --- сверка при старте (F-G-04, AC-03) ---------------------------------------

    pub fn reconcile_at_startup(&mut self) -> Result<ReconcileReport, ServiceError> {
        let seq_local = self.chain.seq().saturating_sub(1);
        let seq_tpm = self.tpm_anchor.latest_seq().ok();
        let seq_ext = self.ext_anchor.latest_seq().ok();
        let tpm_available = self.tpm_anchor.available() && seq_tpm.is_some();
        let ext_available = self.ext_anchor.available() && seq_ext.is_some();
        if ext_available {
            self.ext_tracker.mark_ok();
        } else {
            self.ext_tracker.mark_failure();
        }
        let wear = self.tpm_anchor.wear_percent().unwrap_or(0.0);
        let input = ReconcileInput {
            seq_local,
            seq_tpm,
            seq_ext,
            tpm_available,
            ext_available,
            ext_down_over_threshold: self.ext_tracker.degraded(),
            tpm_wear_percent: wear,
            buffered_checkpoints: self.buffer.len(),
        };
        let report = reconcile(&input);
        if report.verdict == ReconcileVerdict::Truncation {
            // F-G-04: немедленная блокировка записи
            self.chain.set_write_locked(true);
            eprintln!(
                "[worm-audit] TRUNCATION DETECTED: seq_local={seq_local} < anchors(tpm={:?}, ext={:?}) — запись заблокирована, RECOVERY (AC-03)",
                seq_tpm, seq_ext
            );
        }
        Ok(report)
    }

    // --- верификация и статус ------------------------------------------------------

    pub fn verify(&self, deep: bool, signatures: bool, from_seq: u64, to_seq: u64) -> VerifyReport {
        crate::chain::verify_chain(
            self.chain.path(),
            deep,
            signatures,
            Some(self.chain.signer()),
            from_seq,
            to_seq,
        )
    }

    pub fn anchor_status(&mut self) -> AnchorStatus {
        let mut status = AnchorStatus::default();
        status.seq_tpm = self.tpm_anchor.latest_seq().unwrap_or(0);
        status.tpm_available = self.tpm_anchor.available();
        status.tpm_nv_wear_percent = self.tpm_anchor.wear_percent().unwrap_or(0.0);
        status.seq_ext = self.ext_anchor.latest_seq().unwrap_or(0);
        status.ext_available = self.ext_anchor.available();
        status.buffered_checkpoints = self.buffer.len();
        status.tpm_last_write_unix_ns = self
            .tpm_anchor
            .last_write()
            .and_then(|t| t.checked_add(Duration::ZERO))
            .map(|_| crate::record::now_unix_ns())
            .unwrap_or(0);
        status
    }

    pub fn stats(&self) -> ChainStats {
        self.chain.stats()
    }

    pub fn last_checkpoint(&self) -> Option<&Checkpoint> {
        self.last_checkpoint.as_ref()
    }

    pub fn chain(&self) -> &ChainWriter {
        &self.chain
    }

    pub fn chain_mut(&mut self) -> &mut ChainWriter {
        &mut self.chain
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    pub fn ext_degraded(&self) -> bool {
        self.ext_tracker.degraded()
    }

    // --- ingestion спулов (bootstrap/egress/gateway) -------------------------------

    /// Поглотить JSONL-спул (ztbootstrap.events / llm-gateway egress log):
    /// каждая строка становится записью цепочки соответствующего kind.
    pub fn ingest_spool(&mut self, path: impl AsRef<Path>, remove_after: bool) -> Result<u64, ServiceError> {
        let file = match std::fs::File::open(path.as_ref()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(ServiceError::Io(e)),
        };
        let reader = BufReader::new(file);
        let mut count = 0u64;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue, // мусор в хвосте (torn write) — пропускаем
            };
            let kind = RecordKind::parse(
                value.get("kind").and_then(|k| k.as_str()).unwrap_or("UNSPECIFIED"),
            );
            let source = value.get("source").and_then(|s| s.as_str()).unwrap_or("spool");
            let subject = value.get("subject").and_then(|s| s.as_str()).unwrap_or("unknown");
            let payload = serde_json::to_vec(value.get("payload").unwrap_or(&value))
                .map_err(|e| ServiceError::Serde(e.to_string()))?;
            self.append(&payload, kind, source, subject)?;
            count += 1;
        }
        if remove_after && count > 0 {
            std::fs::remove_file(path.as_ref())?;
        }
        Ok(count)
    }
}

fn append_checkpoint_file(path: &Path, cp: &Checkpoint) -> Result<(), ServiceError> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(cp).map_err(|e| ServiceError::Serde(e.to_string()))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

fn read_last_checkpoint(path: &Path) -> Result<Option<Checkpoint>, ServiceError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ServiceError::Io(e)),
    };
    let reader = BufReader::new(file);
    let mut last = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(cp) = serde_json::from_str::<Checkpoint>(&line) {
            last = Some(cp);
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchors::DirectoryAnchor;
    use crate::chain::{ChainConfig, SeedSigner, SyncPolicy};
    use zt_hal_common::tpm::MockTpm;

    type TestService = AuditService<MockTpm, DirectoryAnchor>;

    fn test_signer() -> Box<dyn ChainSigner> {
        Box::new(SeedSigner::from_seed(*b"zt-worm-service-test-seed-000001"))
    }

    fn service(dir: &tempfile::TempDir, cfg: ServiceConfig) -> TestService {
        let tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        let ext = DirectoryAnchor::new(dir.path().join("ext")).unwrap();
        AuditService::open(
            dir.path().join("chain.jsonl"),
            dir.path().join("checkpoints.jsonl"),
            dir.path().join("buffer"),
            tpm,
            ext,
            test_signer(),
            cfg,
        )
        .unwrap()
    }

    fn fast_cfg() -> ServiceConfig {
        ServiceConfig {
            chain: ChainConfig {
                sync_policy: SyncPolicy::OnCheckpoint,
                ..Default::default()
            },
            checkpoint_policy: CheckpointPolicy {
                every_records: 10,
                every_interval: Duration::from_secs(3600),
            },
            tpm_nv_index: 0x1500001,
            tpm_min_interval: Duration::ZERO,
            ..Default::default()
        }
    }

    #[test]
    fn append_and_auto_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = service(&dir, fast_cfg());
        for i in 0..10 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Prompt, "t", "s").unwrap();
        }
        // после 10-й записи чекпоинт созрел и опубликован
        let cp = svc.last_checkpoint().expect("чекпоинт обязан опубликоваться");
        assert_eq!(cp.last_seq, 10);
        assert!(cp.verify().unwrap());
        let status = svc.anchor_status();
        assert_eq!(status.seq_ext, 10);
        assert_eq!(status.seq_tpm, 10);
    }

    #[test]
    fn reconcile_ok_after_sync() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = service(&dir, fast_cfg());
        for i in 0..10 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
        }
        let report = svc.reconcile_at_startup().unwrap();
        assert_eq!(report.verdict, ReconcileVerdict::Ok);
        assert!(!report.write_locked);
    }

    #[test]
    fn ac03_truncation_detected_on_restart_and_writes_locked() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut svc = service(&dir, fast_cfg());
            for i in 0..10 {
                svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
            }
            // чекпоинт заякорен: seq_tpm = seq_ext = 10
        }
        // AC-03: злоумышленник удаляет хвост локального лога (5 записей)
        {
            let path = dir.path().join("chain.jsonl");
            let lines: Vec<String> = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .map(String::from)
                .collect();
            std::fs::write(&path, lines[..5].join("\n") + "\n").unwrap();
        }
        // рестарт: сверка обязана обнаружить truncation
        let mut svc = service(&dir, fast_cfg());
        let report = svc.reconcile_at_startup().unwrap();
        assert_eq!(report.verdict, ReconcileVerdict::Truncation);
        assert!(report.write_locked);
        assert_eq!(report.seq_local, 5);
        assert!(report.anchors.seq_tpm >= 10 || report.anchors.seq_ext >= 10);
        // запись заблокирована
        let err = svc.append(b"new", RecordKind::Ipc, "t", "s").unwrap_err();
        assert!(matches!(err, ServiceError::Chain(ChainError::WriteLocked)));
    }

    #[test]
    fn unanchored_tail_publishes_on_demand() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = service(&dir, fast_cfg());
        for i in 0..10 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
        }
        for i in 10..15 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
        }
        // хвост 11..15 не заякорен
        let report = svc.reconcile_at_startup().unwrap();
        assert_eq!(report.verdict, ReconcileVerdict::UnanchoredTail);
        assert!(!report.write_locked);
        // публикация при первой возможности
        let outcome = svc.publish_checkpoint(true, true, true).unwrap();
        assert!(outcome.published && outcome.ext_anchored);
        let report2 = svc.reconcile_at_startup().unwrap();
        assert_eq!(report2.verdict, ReconcileVerdict::Ok);
    }

    #[test]
    fn chaos_d_ext_anchor_down_buffers_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        let mut ext = DirectoryAnchor::new(dir.path().join("ext")).unwrap();
        ext.set_online(false); // S3 → 503
        let mut svc = AuditService::open(
            dir.path().join("chain.jsonl"),
            dir.path().join("checkpoints.jsonl"),
            dir.path().join("buffer"),
            tpm,
            ext,
            test_signer(),
            fast_cfg(),
        )
        .unwrap();
        for i in 0..10 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
        }
        let outcome = svc.publish_checkpoint(true, true, true).unwrap();
        assert!(outcome.published);
        assert!(outcome.buffered, "чекпоинт обязан уйти в локальный буфер");
        assert!(!outcome.ext_anchored);
        assert_eq!(svc.anchor_status().buffered_checkpoints, 1);
        // восстановление S3 → следующий publish сливает буфер
        svc.ext_anchor.set_online(true);
        let outcome2 = svc.publish_checkpoint(true, true, true).unwrap();
        assert!(outcome2.ext_anchored);
        assert_eq!(svc.anchor_status().buffered_checkpoints, 0);
    }

    #[test]
    fn chaos_c_tpm_failure_leaves_s3_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let mut tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        tpm.set_online(false); // TPM NV write failure
        let ext = DirectoryAnchor::new(dir.path().join("ext")).unwrap();
        let mut svc = AuditService::open(
            dir.path().join("chain.jsonl"),
            dir.path().join("checkpoints.jsonl"),
            dir.path().join("buffer"),
            tpm,
            ext,
            test_signer(),
            fast_cfg(),
        )
        .unwrap();
        for i in 0..10 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
        }
        let outcome = svc.publish_checkpoint(true, true, true).unwrap();
        assert!(outcome.published);
        assert!(outcome.ext_anchored, "S3-якорь обязан принять чекпоинт");
        assert!(!outcome.tpm_anchored);
        let report = svc.reconcile_at_startup().unwrap();
        assert_eq!(report.verdict, ReconcileVerdict::TpmAnchorDown);
    }

    #[test]
    fn tpm_rate_limit_one_per_hour() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = fast_cfg();
        cfg.tpm_min_interval = Duration::from_secs(3600); // боевой лимит
        // авто-публикацию отключаем — чекпоинты только принудительные
        cfg.checkpoint_policy.every_records = 1000;
        let mut svc = service(&dir, cfg);
        for i in 0..10 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
        }
        let o1 = svc.publish_checkpoint(true, true, true).unwrap();
        assert!(o1.tpm_anchored);
        for i in 10..20 {
            svc.append(format!("r{i}").as_bytes(), RecordKind::Ipc, "t", "s").unwrap();
        }
        let o2 = svc.publish_checkpoint(true, true, true).unwrap();
        assert!(o2.published && o2.ext_anchored);
        assert!(!o2.tpm_anchored, "F-G-05: вторая TPM-запись в пределах часа запрещена");
    }

    #[test]
    fn spool_ingestion_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = service(&dir, fast_cfg());
        let spool = dir.path().join("spool.jsonl");
        let lines = [
            r#"{"ts_ns":1,"kind":"RECORD_KIND_BOOTSTRAP","source":"t8-sandbox/bootstrap","subject":"d8","payload":{"stage":"START"}}"#,
            r#"{"ts_ns":2,"kind":"RECORD_KIND_INTEGRITY","source":"t8-sandbox/bootstrap","subject":"d8","payload":{"interpreter_sha256":"ab"}}"#,
            "garbage-not-json{{{",
        ];
        std::fs::write(&spool, lines.join("\n") + "\n").unwrap();
        let n = svc.ingest_spool(&spool, false).unwrap();
        assert_eq!(n, 2, "мусорная строка пропускается, валидные — в цепочку");
        let report = svc.verify(true, true, 0, 0);
        assert!(report.valid, "{report:?}");
    }

    #[test]
    fn verify_deep_with_signatures() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = service(&dir, fast_cfg());
        for i in 0..50 {
            svc.append(format!("payload-{i}").as_bytes(), RecordKind::Response, "rag", "d8")
                .unwrap();
        }
        let report = svc.verify(true, true, 0, 0);
        assert!(report.valid, "{report:?}");
        assert_eq!(report.records_checked, 50);
    }

    #[test]
    fn peek_next_seq_tracks_chain_growth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.jsonl");
        assert_eq!(crate::chain::peek_next_seq(&path).unwrap(), 1);
        {
            let mut w = ChainWriter::open(&path, ChainConfig::default(), test_signer()).unwrap();
            w.append(b"x", RecordKind::Ipc, "s", "u", None, None).unwrap();
            w.append(b"y", RecordKind::Ipc, "s", "u", None, None).unwrap();
            w.sync_now().unwrap();
        }
        assert_eq!(crate::chain::peek_next_seq(&path).unwrap(), 3);
    }
}
