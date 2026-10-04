//! Тепловой бюджет (F-H-04, NF-08, docs/09-hal-thermal.md).
//!
//! `T_j ≤ 75 °C`, derating ≥ 20% от даташита, аппаратный троттлинг всегда
//! включён. ПО лишь планирует нагрузку и инициирует переходы FSM.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Предел температуры кристалла (NF-08).
pub const MAX_TJ_C: f64 = 75.0;
/// Минимальный derating от даташита (F-H-04).
pub const MIN_DERATING: f64 = 0.20;

#[derive(Debug, Error)]
pub enum ThermalError {
    #[error("thermal zone not readable: {0}")]
    Unreadable(String),
    #[error("no thermal source available")]
    NoSource,
}

/// Действие планировщика по температуре (docs/09 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThermalAction {
    /// T_j < 60: полная нагрузка (NOMINAL).
    Nominal,
    /// 60 ≤ T_j < 70: предупреждение, снижение batch/top_k.
    Warn,
    /// 70 ≤ T_j ≤ 75: DEGRADED + derating ≥ 20%.
    Derate,
    /// T_j > 75: принудительный троттлинг + ISOLATED.
    ThrottleIsolate,
    /// Повторных превышений > 3/мин: SHUTDOWN.
    EmergencyShutdown,
}

/// Бюджет: пороги и derating.
#[derive(Debug, Clone)]
pub struct ThermalBudget {
    pub max_tj_c: f64,
    pub derating: f64,
    pub warn_c: f64,
    pub derate_c: f64,
    /// Порог «аварийного» счётчика: сколько ThrottleIsolate подряд/за окно
    /// до EmergencyShutdown.
    pub emergency_strikes: u32,
}

impl Default for ThermalBudget {
    fn default() -> Self {
        Self {
            max_tj_c: MAX_TJ_C,
            derating: 0.25, // ≥ 20% с запасом
            warn_c: 60.0,
            derate_c: 70.0,
            emergency_strikes: 3,
        }
    }
}

impl ThermalBudget {
    pub fn validate(&self) -> Result<(), ThermalError> {
        if self.derating < MIN_DERATING {
            return Err(ThermalError::Unreadable(format!(
                "derating {:.2} < минимальных {:.2} (F-H-04)",
                self.derating, MIN_DERATING
            )));
        }
        if self.max_tj_c > MAX_TJ_C {
            return Err(ThermalError::Unreadable(format!(
                "max_tj {:.1} > предела {:.1} (NF-08)",
                self.max_tj_c, MAX_TJ_C
            )));
        }
        Ok(())
    }

    /// Классификация температуры (без состояния — чистая функция).
    pub fn classify(&self, tj_c: f64) -> ThermalAction {
        if tj_c > self.max_tj_c {
            ThermalAction::ThrottleIsolate
        } else if tj_c >= self.derate_c {
            ThermalAction::Derate
        } else if tj_c >= self.warn_c {
            ThermalAction::Warn
        } else {
            ThermalAction::Nominal
        }
    }

    /// Допустимая доля нагрузки при derating (для планировщика D8).
    pub fn load_factor(&self, action: ThermalAction) -> f64 {
        match action {
            ThermalAction::Nominal => 1.0,
            ThermalAction::Warn => 0.9,
            ThermalAction::Derate => 1.0 - self.derating,
            ThermalAction::ThrottleIsolate => 0.25,
            ThermalAction::EmergencyShutdown => 0.0,
        }
    }
}

/// Источник телеметрии температуры.
pub trait ThermalSource {
    /// Текущая T_j, °C.
    fn read_tj_c(&mut self) -> Result<f64, ThermalError>;
    fn name(&self) -> &str;
}

/// Sysfs-источник: `/sys/class/thermal/thermal_zone*/temp` (миллиградусы).
pub struct SysfsThermal {
    zone_path: PathBuf,
}

impl SysfsThermal {
    /// Первая доступная zone (или явный путь).
    pub fn auto(root: &Path) -> Result<Self, ThermalError> {
        let base = root.join("sys/class/thermal");
        let mut zones: Vec<PathBuf> = std::fs::read_dir(&base)
            .map_err(|e| ThermalError::Unreadable(e.to_string()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().map(|n| n.to_string_lossy().starts_with("thermal_zone")).unwrap_or(false))
            .collect();
        zones.sort();
        let zone = zones
            .into_iter()
            .find(|z| z.join("temp").exists())
            .ok_or(ThermalError::NoSource)?;
        Ok(Self { zone_path: zone.join("temp") })
    }

    pub fn new(zone_temp_path: PathBuf) -> Self {
        Self { zone_path: zone_temp_path }
    }
}

impl ThermalSource for SysfsThermal {
    fn read_tj_c(&mut self) -> Result<f64, ThermalError> {
        let raw = std::fs::read_to_string(&self.zone_path)
            .map_err(|e| ThermalError::Unreadable(format!("{}: {e}", self.zone_path.display())))?;
        let millideg: f64 = raw.trim().parse()
            .map_err(|_| ThermalError::Unreadable(format!("bad temp value: {raw:?}")))?;
        Ok(millideg / 1000.0)
    }

    fn name(&self) -> &str {
        "sysfs"
    }
}

/// Детерминированный источник для тестов/CI.
pub struct MockThermal {
    pub temps: Vec<f64>,
    idx: usize,
}

impl MockThermal {
    pub fn new(temps: Vec<f64>) -> Self {
        Self { temps, idx: 0 }
    }
}

impl ThermalSource for MockThermal {
    fn read_tj_c(&mut self) -> Result<f64, ThermalError> {
        if self.temps.is_empty() {
            return Err(ThermalError::NoSource);
        }
        let t = self.temps[self.idx.min(self.temps.len() - 1)];
        self.idx += 1;
        Ok(t)
    }

    fn name(&self) -> &str {
        "mock"
    }
}

/// Монитор: источник + бюджет + счётчик аварий (эскалация EmergencyShutdown).
pub struct ThermalMonitor<S: ThermalSource> {
    source: S,
    budget: ThermalBudget,
    strikes: u32,
}

impl<S: ThermalSource> ThermalMonitor<S> {
    pub fn new(source: S, budget: ThermalBudget) -> Self {
        Self { source, budget, strikes: 0 }
    }

    /// Один такт опроса: вернуть действие с учётом эскалации.
    pub fn poll(&mut self) -> Result<ThermalAction, ThermalError> {
        let tj = self.source.read_tj_c()?;
        let mut action = self.budget.classify(tj);
        if action == ThermalAction::ThrottleIsolate {
            self.strikes += 1;
            if self.strikes >= self.budget.emergency_strikes {
                action = ThermalAction::EmergencyShutdown;
            }
        } else {
            self.strikes = 0;
        }
        Ok(action)
    }

    pub fn budget(&self) -> &ThermalBudget {
        &self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_boundaries() {
        let b = ThermalBudget::default();
        assert_eq!(b.classify(25.0), ThermalAction::Nominal);
        assert_eq!(b.classify(59.9), ThermalAction::Nominal);
        assert_eq!(b.classify(60.0), ThermalAction::Warn);
        assert_eq!(b.classify(69.9), ThermalAction::Warn);
        assert_eq!(b.classify(70.0), ThermalAction::Derate);
        assert_eq!(b.classify(75.0), ThermalAction::Derate);
        assert_eq!(b.classify(75.1), ThermalAction::ThrottleIsolate);
    }

    #[test]
    fn derating_at_least_20_percent() {
        let b = ThermalBudget::default();
        b.validate().unwrap();
        assert!(b.load_factor(ThermalAction::Derate) <= 0.80);
        let bad = ThermalBudget { derating: 0.10, ..Default::default() };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn escalation_to_emergency_shutdown() {
        let src = MockThermal::new(vec![80.0, 81.0, 82.0, 50.0]);
        let mut mon = ThermalMonitor::new(src, ThermalBudget::default());
        assert_eq!(mon.poll().unwrap(), ThermalAction::ThrottleIsolate);
        assert_eq!(mon.poll().unwrap(), ThermalAction::ThrottleIsolate);
        assert_eq!(mon.poll().unwrap(), ThermalAction::EmergencyShutdown);
    }

    #[test]
    fn strikes_reset_after_cooldown() {
        let src = MockThermal::new(vec![80.0, 80.0, 50.0, 80.0, 80.0]);
        let mut mon = ThermalMonitor::new(src, ThermalBudget::default());
        assert_eq!(mon.poll().unwrap(), ThermalAction::ThrottleIsolate);
        assert_eq!(mon.poll().unwrap(), ThermalAction::ThrottleIsolate);
        assert_eq!(mon.poll().unwrap(), ThermalAction::Nominal);
        assert_eq!(mon.poll().unwrap(), ThermalAction::ThrottleIsolate);
        assert_eq!(mon.poll().unwrap(), ThermalAction::ThrottleIsolate); // счётчик сброшен
    }

    #[test]
    fn sysfs_reads_millidegrees() {
        let dir = tempfile::tempdir().unwrap();
        let zone = dir.path().join("sys/class/thermal/thermal_zone0");
        std::fs::create_dir_all(&zone).unwrap();
        std::fs::write(zone.join("temp"), "42500\n").unwrap();
        let mut src = SysfsThermal::auto(dir.path()).unwrap();
        assert_eq!(src.read_tj_c().unwrap(), 42.5);
    }
}
