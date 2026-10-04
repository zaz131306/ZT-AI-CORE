//! ZT-AI-CORE HAL (L0–L3): общие примитивы аппаратного уровня.
//!
//! Состав (ТЗ v2.4, Раздел 3.6 / docs/09-hal-thermal.md):
//! * [`crypto`]   — криптографический профиль (Приложение Б), счётчик nonce
//!                    AES-256-GCM (F-H-01), политика never-exportable (F-H-03);
//! * [`thermal`]  — тепловой бюджет `T_j ≤ 75 °C`, derating ≥ 20% (F-H-04, NF-08);
//! * [`power`]    — энергетические бюджеты режимов (NF-07);
//! * [`platform`] — детекция архитектуры/glibc/Jetson (F-E-08, Раздел 0);
//! * [`tpm`]      — операции TPM 2.0: NV-Counter, PCR[0-15], Quote,
//!                    подпись Ed25519 без экспорта ключа (F-H-03/05, F-G-05).
//!
//! Продакшен-реализация TPM подключается на целевом железе (tss2/tpm2-tools);
//! [`tpm::MockTpm`] — детерминированная файловая реализация для CI и стендов
//! (монотонные NV-счётчики, износ ячейки, PCR-extend, Ed25519-подпись).

pub mod crypto;
pub mod platform;
pub mod power;
pub mod thermal;
pub mod tpm;

/// Версия спецификации, реализуемая крейтом.
pub const SPEC_VERSION: &str = "2.4";

pub use crypto::{CryptoProfile, MonotonicNonce96};
pub use platform::{Arch, PlatformInfo};
pub use power::{PowerBudget, PowerModeContext};
pub use thermal::{ThermalAction, ThermalBudget, ThermalSource};
pub use tpm::{MockTpm, TpmError, TpmOps};
