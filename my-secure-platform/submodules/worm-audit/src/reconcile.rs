//! Anti-truncation сверка при старте (F-G-04, AC-03) и политика деградации.
//!
//! | Условие                                   | Вердикт           | Действие                             |
//! |-------------------------------------------|-------------------|--------------------------------------|
//! | `seq_TPM > seq_local` ИЛИ `seq_ext > seq_local` | **TRUNCATION** | RECOVERY, блокировка записи, CISO |
//! | `seq_local > seq_ext`                     | UNANCHORED_TAIL   | публикация чекпоинта при первой возможности |
//! | Внешний якорь недоступен > 5 мин          | EXT_ANCHOR_DOWN   | DEGRADED, буферизация чекпоинтов     |
//! | TPM NV недоступен                         | TPM_ANCHOR_DOWN   | чекпоинты только в S3, DEGRADED      |
//! | Износ NV ≥ 80%                            | (флаг wear_alert) | DEGRADED + алерт (F-G-05)            |

use serde::{Deserialize, Serialize};

use crate::anchors::AnchorStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconcileVerdict {
    Unspecified,
    Ok,
    UnanchoredTail,
    Truncation,
    ExtAnchorDown,
    TpmAnchorDown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub verdict: ReconcileVerdict,
    pub seq_local: u64,
    pub anchors: AnchorStatus,
    pub action: String,
    pub write_locked: bool,
    pub wear_alert: bool,
    pub timestamp_unix_ns: i64,
}

/// Вход сверки: локальный seq + состояния обоих якорей.
#[derive(Debug, Clone)]
pub struct ReconcileInput {
    pub seq_local: u64,
    /// None — якорь недоступен (чтение seq не удалось).
    pub seq_tpm: Option<u64>,
    pub seq_ext: Option<u64>,
    pub tpm_available: bool,
    pub ext_available: bool,
    /// Внешний якорь непрерывно недоступен дольше порога (5 мин).
    pub ext_down_over_threshold: bool,
    pub tpm_wear_percent: f64,
    pub buffered_checkpoints: usize,
}

/// Чистая функция сверки (F-G-04) — детерминирована, полностью покрыта тестами.
pub fn reconcile(input: &ReconcileInput) -> ReconcileReport {
    let wear_alert = input.tpm_wear_percent >= 80.0;

    let anchors = AnchorStatus {
        seq_tpm: input.seq_tpm.unwrap_or(0),
        seq_ext: input.seq_ext.unwrap_or(0),
        tpm_last_write_unix_ns: 0,
        tpm_nv_wear_percent: input.tpm_wear_percent,
        tpm_available: input.tpm_available,
        ext_available: input.ext_available,
        ext_last_ok_unix_ns: 0,
        buffered_checkpoints: input.buffered_checkpoints,
    };

    // 1. TRUNCATION — наивысший приоритет (инцидент безопасности).
    let tpm_ahead = input.seq_tpm.map(|s| s > input.seq_local).unwrap_or(false);
    let ext_ahead = input.seq_ext.map(|s| s > input.seq_local).unwrap_or(false);
    if tpm_ahead || ext_ahead {
        return ReconcileReport {
            verdict: ReconcileVerdict::Truncation,
            seq_local: input.seq_local,
            anchors,
            action: "systemctl start zt-recovery.service; блокировка записи; эскалация в CISO (runbook §2)"
                .to_string(),
            write_locked: true,
            wear_alert,
            timestamp_unix_ns: crate::record::now_unix_ns(),
        };
    }

    // 2. Внешний якорь недоступен > 5 мин → DEGRADED (запись продолжается).
    if input.ext_down_over_threshold {
        return ReconcileReport {
            verdict: ReconcileVerdict::ExtAnchorDown,
            seq_local: input.seq_local,
            anchors,
            action: "FSM → DEGRADED; чекпоинты в локальный защищённый буфер; эскалация SRE > 30 мин"
                .to_string(),
            write_locked: false,
            wear_alert,
            timestamp_unix_ns: crate::record::now_unix_ns(),
        };
    }

    // 3. TPM недоступен → чекпоинты только в S3, DEGRADED до восстановления.
    if !input.tpm_available {
        return ReconcileReport {
            verdict: ReconcileVerdict::TpmAnchorDown,
            seq_local: input.seq_local,
            anchors,
            action: "FSM → DEGRADED; чекпоинты только в S3; после восстановления: zt-core-cli sync-tpm-nv"
                .to_string(),
            write_locked: false,
            wear_alert,
            timestamp_unix_ns: crate::record::now_unix_ns(),
        };
    }

    // 4. Неподтверждённый хвост — норма; публикация чекпоинта при первой возможности.
    let seq_ext = input.seq_ext.unwrap_or(0);
    if input.seq_local > seq_ext {
        return ReconcileReport {
            verdict: ReconcileVerdict::UnanchoredTail,
            seq_local: input.seq_local,
            anchors,
            action: "публикация нового чекпоинта при первой возможности (F-G-04)".to_string(),
            write_locked: false,
            wear_alert,
            timestamp_unix_ns: crate::record::now_unix_ns(),
        };
    }

    // 5. Всё синхронизировано.
    ReconcileReport {
        verdict: ReconcileVerdict::Ok,
        seq_local: input.seq_local,
        anchors,
        action: String::new(),
        write_locked: false,
        wear_alert,
        timestamp_unix_ns: crate::record::now_unix_ns(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> ReconcileInput {
        ReconcileInput {
            seq_local: 1000,
            seq_tpm: Some(1000),
            seq_ext: Some(1000),
            tpm_available: true,
            ext_available: true,
            ext_down_over_threshold: false,
            tpm_wear_percent: 10.0,
            buffered_checkpoints: 0,
        }
    }

    #[test]
    fn all_synced_is_ok() {
        let r = reconcile(&base_input());
        assert_eq!(r.verdict, ReconcileVerdict::Ok);
        assert!(!r.write_locked);
    }

    #[test]
    fn ac03_tpm_ahead_is_truncation_with_write_lock() {
        let mut i = base_input();
        i.seq_local = 500;   // хвост лога удалён
        i.seq_tpm = Some(1000);
        let r = reconcile(&i);
        assert_eq!(r.verdict, ReconcileVerdict::Truncation);
        assert!(r.write_locked, "AC-03: блокировка записи обязательна");
        assert!(r.action.contains("zt-recovery"));
    }

    #[test]
    fn ac03_ext_ahead_is_truncation() {
        let mut i = base_input();
        i.seq_local = 999;
        i.seq_ext = Some(1000);
        let r = reconcile(&i);
        assert_eq!(r.verdict, ReconcileVerdict::Truncation);
        assert!(r.write_locked);
    }

    #[test]
    fn unanchored_tail_is_normal() {
        let mut i = base_input();
        i.seq_local = 1500;
        i.seq_ext = Some(1000);
        i.seq_tpm = Some(1000);
        let r = reconcile(&i);
        assert_eq!(r.verdict, ReconcileVerdict::UnanchoredTail);
        assert!(!r.write_locked);
        assert!(r.action.contains("чекпоинт"));
    }

    #[test]
    fn ext_anchor_down_over_5min_degrades() {
        let mut i = base_input();
        i.ext_available = false;
        i.seq_ext = None;
        i.ext_down_over_threshold = true;
        let r = reconcile(&i);
        assert_eq!(r.verdict, ReconcileVerdict::ExtAnchorDown);
        assert!(!r.write_locked, "запись продолжается, чекпоинты буферизуются");
    }

    #[test]
    fn ext_anchor_briefly_down_is_not_degraded() {
        let mut i = base_input();
        i.ext_available = false;
        i.seq_ext = Some(1000);
        i.ext_down_over_threshold = false; // < 5 минут
        let r = reconcile(&i);
        assert_eq!(r.verdict, ReconcileVerdict::Ok);
    }

    #[test]
    fn tpm_anchor_down_degrades() {
        let mut i = base_input();
        i.tpm_available = false;
        i.seq_tpm = None;
        let r = reconcile(&i);
        assert_eq!(r.verdict, ReconcileVerdict::TpmAnchorDown);
        assert!(r.action.contains("sync-tpm-nv"));
    }

    #[test]
    fn truncation_takes_priority_over_anchor_down() {
        let mut i = base_input();
        i.seq_local = 10;
        i.seq_tpm = Some(1000);
        i.ext_down_over_threshold = true;
        let r = reconcile(&i);
        assert_eq!(r.verdict, ReconcileVerdict::Truncation);
    }

    #[test]
    fn wear_alert_flag_at_80_percent() {
        let mut i = base_input();
        i.tpm_wear_percent = 80.0;
        let r = reconcile(&i);
        assert!(r.wear_alert, "F-G-05: износ ≥ 80% → алерт");
        let mut i2 = base_input();
        i2.tpm_wear_percent = 79.9;
        assert!(!reconcile(&i2).wear_alert);
    }
}
