//! Энергетические бюджеты (NF-07, Jetson Orin NX).
//!
//! | Режим                    | Бюджет  |
//! |--------------------------|---------|
//! | NOMINAL (RAG + LLM)      | ≤ 25 Вт |
//! | NOMINAL (только RAG)     | ≤ 10 Вт |
//! | ISOLATED                 | ≤ 5 Вт  |
//! | DEGRADED                 | ≤ 3 Вт  |

/// Контекст нагрузки NOMINAL-режима.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerModeContext {
    /// RAG + локальный LLM-инференс.
    NominalFull,
    /// Только RAG (LLM простаивает/выгружен).
    NominalRagOnly,
    /// Изоляция (payload остановлен, шина жива).
    Isolated,
    /// Деградация (минимальное ядро: FSM + WORM).
    Degraded,
    /// Завершение.
    Shutdown,
}

/// Бюджет мощности в ваттах.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PowerBudget {
    pub context: PowerModeContext,
    pub watts: f64,
}

impl PowerBudget {
    /// Бюджет по NF-07 ( Jetson Orin NX).
    pub fn for_mode(ctx: PowerModeContext) -> Self {
        let watts = match ctx {
            PowerModeContext::NominalFull => 25.0,
            PowerModeContext::NominalRagOnly => 10.0,
            PowerModeContext::Isolated => 5.0,
            PowerModeContext::Degraded => 3.0,
            PowerModeContext::Shutdown => 1.0,
        };
        Self { context: ctx, watts }
    }

    /// Проверка фактического потребления: превышение → true (планировщик
    /// обязан снизить нагрузку, затем FSM инициирует DEGRADED).
    pub fn exceeded_by(&self, measured_watts: f64) -> bool {
        measured_watts > self.watts
    }
}

/// Память D8 (NF-06): модель 14B — ≤ 12 ГБ.
pub const D8_MEMORY_MAX_BYTES: u64 = 12 * 1024 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nf07_budgets() {
        assert_eq!(PowerBudget::for_mode(PowerModeContext::NominalFull).watts, 25.0);
        assert_eq!(PowerBudget::for_mode(PowerModeContext::NominalRagOnly).watts, 10.0);
        assert_eq!(PowerBudget::for_mode(PowerModeContext::Isolated).watts, 5.0);
        assert_eq!(PowerBudget::for_mode(PowerModeContext::Degraded).watts, 3.0);
    }

    #[test]
    fn budgets_are_monotonic() {
        let full = PowerBudget::for_mode(PowerModeContext::NominalFull).watts;
        let rag = PowerBudget::for_mode(PowerModeContext::NominalRagOnly).watts;
        let iso = PowerBudget::for_mode(PowerModeContext::Isolated).watts;
        let deg = PowerBudget::for_mode(PowerModeContext::Degraded).watts;
        assert!(full > rag && rag > iso && iso > deg);
    }

    #[test]
    fn exceedance_detection() {
        let b = PowerBudget::for_mode(PowerModeContext::Degraded);
        assert!(b.exceeded_by(3.5));
        assert!(!b.exceeded_by(2.9));
    }
}
