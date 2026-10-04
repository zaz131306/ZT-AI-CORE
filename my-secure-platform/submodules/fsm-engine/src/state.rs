//! Пространство состояний FSM: Lifecycle × Operating Modes (F-F-01/02,
//! Приложение А ТЗ), граф допустимых переходов lifecycle.

use serde::{Deserialize, Serialize};

/// Жизненный цикл (F-F-01): BOOT → BOOT_FAILSAFE → SELF_TEST → RUNNING →
/// DEGRADED → SHUTDOWN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Boot,
    BootFailsafe,
    SelfTest,
    Running,
    Degraded,
    Shutdown,
}

/// Операционные режимы (F-F-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperatingMode {
    Nominal,
    Isolated,
    Recovery,
}

impl LifecycleState {
    pub const ALL: [LifecycleState; 6] = [
        LifecycleState::Boot,
        LifecycleState::BootFailsafe,
        LifecycleState::SelfTest,
        LifecycleState::Running,
        LifecycleState::Degraded,
        LifecycleState::Shutdown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleState::Boot => "BOOT",
            LifecycleState::BootFailsafe => "BOOT_FAILSAFE",
            LifecycleState::SelfTest => "SELF_TEST",
            LifecycleState::Running => "RUNNING",
            LifecycleState::Degraded => "DEGRADED",
            LifecycleState::Shutdown => "SHUTDOWN",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str().eq_ignore_ascii_case(s))
    }
}

impl OperatingMode {
    pub const ALL: [OperatingMode; 3] = [
        OperatingMode::Nominal,
        OperatingMode::Isolated,
        OperatingMode::Recovery,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            OperatingMode::Nominal => "NOMINAL",
            OperatingMode::Isolated => "ISOLATED",
            OperatingMode::Recovery => "RECOVERY",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str().eq_ignore_ascii_case(s))
    }
}

impl std::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Приложение А: матрица допустимых комбинаций Lifecycle × Mode.
///
/// | Lifecycle \ Mode | NOMINAL | ISOLATED | RECOVERY |
/// |---|---|---|---|
/// | BOOT          | ✅ | ❌ | ❌ |
/// | BOOT_FAILSAFE | ❌ | ❌ | ✅ |
/// | SELF_TEST     | ✅ | ✅ | ❌ |
/// | RUNNING       | ✅ | ✅ | ✅ |
/// | DEGRADED      | ❌ | ✅ | ✅ |
/// | SHUTDOWN      | ✅ | ✅ | ✅ |
pub fn matrix_allowed(lifecycle: LifecycleState, mode: OperatingMode) -> bool {
    use LifecycleState as L;
    use OperatingMode as M;
    match (lifecycle, mode) {
        (L::Boot, M::Nominal) => true,
        (L::BootFailsafe, M::Recovery) => true,
        (L::SelfTest, M::Nominal) | (L::SelfTest, M::Isolated) => true,
        (L::Running, _) => true,
        (L::Degraded, M::Isolated) | (L::Degraded, M::Recovery) => true,
        (L::Shutdown, _) => true,
        _ => false,
    }
}

/// Допустимые рёбра графа lifecycle (docs/05-fsm-matrix.md §3).
/// Смена только режима (lifecycle тот же) разрешена отдельно в
/// [`transition_allowed`].
pub fn lifecycle_edge_allowed(from: LifecycleState, to: LifecycleState) -> bool {
    use LifecycleState as L;
    matches!(
        (from, to),
        (L::Boot, L::BootFailsafe)
            | (L::Boot, L::SelfTest)
            | (L::Boot, L::Shutdown)
            | (L::BootFailsafe, L::SelfTest)
            | (L::BootFailsafe, L::Shutdown)
            | (L::SelfTest, L::Running)
            | (L::SelfTest, L::BootFailsafe)
            | (L::SelfTest, L::Degraded)
            | (L::SelfTest, L::Shutdown)
            | (L::Running, L::Degraded)
            | (L::Running, L::SelfTest)
            | (L::Running, L::Shutdown)
            | (L::Degraded, L::SelfTest)
            | (L::Degraded, L::Shutdown)
    )
}

/// Полная проверка перехода: целевая комбинация валидна по Приложению А И
/// (lifecycle не меняется ИЛИ существует ребро графа).
pub fn transition_allowed(
    from: (LifecycleState, OperatingMode),
    to: (LifecycleState, OperatingMode),
) -> bool {
    if !matrix_allowed(to.0, to.1) {
        return false;
    }
    if from.0 == to.0 {
        // смена только режима — допустима (например RUNNING×NOMINAL →
        // RUNNING×RECOVERY при truncation WORM)
        return true;
    }
    lifecycle_edge_allowed(from.0, to.0)
}

/// Триггеры переходов (fsm.proto:TransitionTrigger).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransitionTrigger {
    Unspecified,
    Operator,
    BootOk,
    IntegrityFail,
    SelfTestPass,
    SelfTestFail,
    WormTruncation,
    WalIncomplete,
    ExtAnchorDown,
    TpmWearHigh,
    GatewayDown,
    WatchdogTimeout,
    Thermal,
    ShutdownRequested,
}

impl TransitionTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            TransitionTrigger::Unspecified => "TRIGGER_UNSPECIFIED",
            TransitionTrigger::Operator => "TRIGGER_OPERATOR",
            TransitionTrigger::BootOk => "TRIGGER_BOOT_OK",
            TransitionTrigger::IntegrityFail => "TRIGGER_INTEGRITY_FAIL",
            TransitionTrigger::SelfTestPass => "TRIGGER_SELF_TEST_PASS",
            TransitionTrigger::SelfTestFail => "TRIGGER_SELF_TEST_FAIL",
            TransitionTrigger::WormTruncation => "TRIGGER_WORM_TRUNCATION",
            TransitionTrigger::WalIncomplete => "TRIGGER_WAL_INCOMPLETE",
            TransitionTrigger::ExtAnchorDown => "TRIGGER_EXT_ANCHOR_DOWN",
            TransitionTrigger::TpmWearHigh => "TRIGGER_TPM_WEAR_HIGH",
            TransitionTrigger::GatewayDown => "TRIGGER_GATEWAY_DOWN",
            TransitionTrigger::WatchdogTimeout => "TRIGGER_WATCHDOG_TIMEOUT",
            TransitionTrigger::Thermal => "TRIGGER_THERMAL",
            TransitionTrigger::ShutdownRequested => "TRIGGER_SHUTDOWN_REQUESTED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use LifecycleState as L;
    use OperatingMode as M;

    /// Эталон Приложения А (✅/❌) — независимая таблица для сверки.
    const APPENDIX_A: [[bool; 3]; 6] = [
        // NOMINAL, ISOLATED, RECOVERY
        [true, false, false],  // BOOT
        [false, false, true],  // BOOT_FAILSAFE
        [true, true, false],   // SELF_TEST
        [true, true, true],    // RUNNING
        [false, true, true],   // DEGRADED
        [true, true, true],    // SHUTDOWN
    ];

    #[test]
    fn matrix_matches_appendix_a_exhaustively() {
        for (li, l) in L::ALL.iter().enumerate() {
            for (mi, m) in M::ALL.iter().enumerate() {
                assert_eq!(
                    matrix_allowed(*l, *m),
                    APPENDIX_A[li][mi],
                    "Приложение А нарушено для {l}×{m}"
                );
            }
        }
    }

    #[test]
    fn forbidden_combinations_rejected() {
        assert!(!matrix_allowed(L::Boot, M::Isolated));
        assert!(!matrix_allowed(L::Boot, M::Recovery));
        assert!(!matrix_allowed(L::BootFailsafe, M::Nominal));
        assert!(!matrix_allowed(L::SelfTest, M::Recovery));
        assert!(!matrix_allowed(L::Degraded, M::Nominal));
    }

    #[test]
    fn mode_only_transition_allowed_when_matrix_ok() {
        assert!(transition_allowed((L::Running, M::Nominal), (L::Running, M::Recovery)));
        assert!(transition_allowed((L::Running, M::Nominal), (L::Running, M::Isolated)));
        // BOOT×RECOVERY запрещён матрицей — даже как mode-only
        assert!(!transition_allowed((L::Boot, M::Nominal), (L::Boot, M::Recovery)));
    }

    #[test]
    fn lifecycle_edges_follow_graph() {
        assert!(transition_allowed((L::Boot, M::Nominal), (L::SelfTest, M::Nominal)));
        assert!(transition_allowed((L::Boot, M::Nominal), (L::BootFailsafe, M::Recovery)));
        assert!(transition_allowed((L::SelfTest, M::Nominal), (L::Running, M::Nominal)));
        assert!(transition_allowed((L::Running, M::Nominal), (L::Degraded, M::Isolated)));
        assert!(transition_allowed((L::Degraded, M::Isolated), (L::SelfTest, M::Isolated)));
        assert!(transition_allowed((L::BootFailsafe, M::Recovery), (L::SelfTest, M::Nominal)));
        // запрещённые рёбра
        assert!(!transition_allowed((L::Boot, M::Nominal), (L::Running, M::Nominal)));
        assert!(!transition_allowed((L::Running, M::Nominal), (L::Boot, M::Nominal)));
        // SHUTDOWN терминален
        assert!(!lifecycle_edge_allowed(L::Shutdown, L::Running));
    }

    #[test]
    fn state_parsing_roundtrip() {
        for l in L::ALL {
            assert_eq!(L::parse(l.as_str()), Some(l));
        }
        for m in M::ALL {
            assert_eq!(M::parse(m.as_str()), Some(m));
        }
        assert_eq!(L::parse("running"), Some(L::Running));
        assert_eq!(L::parse("NOPE"), None);
    }

    #[test]
    fn serde_names_match_proto() {
        assert_eq!(
            serde_json::to_string(&L::BootFailsafe).unwrap(),
            "\"BOOT_FAILSAFE\""
        );
        assert_eq!(serde_json::to_string(&M::Recovery).unwrap(), "\"RECOVERY\"");
    }
}
