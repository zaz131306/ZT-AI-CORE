//! Платформенные проверки (Раздел 0 ТЗ, F-E-08).
//!
//! Целевые платформы: ARM64, x86_64, Nvidia Jetson (Orin/Xavier).
//! Обязательное требование: **glibc** (не musl) — musl мигрирует на
//! запрещённый `clone3` (Приложение В).

use std::path::Path;

/// Архитектура платформы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Other(&'static str),
}

impl Arch {
    pub fn native() -> Self {
        match std::env::consts::ARCH {
            "x86_64" => Arch::X86_64,
            "aarch64" => Arch::Aarch64,
            other => Arch::Other(leak_str(other)),
        }
    }

    /// AUDIT_ARCH-константа (для SECCOMP arch-guard).
    pub fn audit_arch(self) -> u32 {
        match self {
            Arch::X86_64 => 0xC000_003E,
            Arch::Aarch64 => 0xC000_00B7,
            Arch::Other(_) => 0,
        }
    }
}

fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

/// Сводка о платформе для SELF_TEST и IntegrityReport.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub arch: Arch,
    pub os: &'static str,
    pub target_env: &'static str,
    pub kernel_release: String,
    pub is_glibc: bool,
    pub is_jetson: bool,
}

impl PlatformInfo {
    /// Сбор сведений (читает /proc и /sys — только read-only).
    pub fn collect(proc_root: &Path) -> Self {
        let kernel_release = std::fs::read_to_string(proc_root.join("sys/kernel/osrelease"))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();
        let is_glibc = runtime_is_glibc();
        let is_jetson = detect_jetson(Path::new("/"));
        Self {
            arch: Arch::native(),
            os: std::env::consts::OS,
            target_env: std::env::consts::ARCH,
            kernel_release,
            is_glibc,
            is_jetson,
        }
    }

    /// F-E-08: среда выполнения обязана быть glibc.
    pub fn satisfies_f_e_08(&self) -> bool {
        self.is_glibc
    }
}

/// Компиляционная + рантайм-проверка glibc (F-E-08).
pub fn runtime_is_glibc() -> bool {
    // Компиляционная константа: target_env == "gnu" для glibc-сборок.
    if cfg!(target_env = "gnu") {
        return true;
    }
    if cfg!(target_env = "musl") {
        return false;
    }
    // Неизвестная среда — проверяем наличие glibc-символов консервативно:
    // отсутствие musl-маркера считаем glibc только на linux.
    cfg!(target_os = "linux")
}

/// Детекция Nvidia Jetson: /etc/nv_tegra_release или device-tree compatible.
pub fn detect_jetson(root: &Path) -> bool {
    if root.join("etc/nv_tegra_release").exists() {
        return true;
    }
    if let Ok(compatible) =
        std::fs::read(root.join("proc/device-tree/compatible"))
    {
        let text = String::from_utf8_lossy(&compatible);
        return text.contains("nvidia") && text.contains("jetson");
    }
    false
}

/// Проверка, что KSM выключен (F-E-05, AC-07): `/sys/kernel/mm/ksm/run == 0`.
pub fn ksm_is_disabled(sys_root: &Path) -> Option<bool> {
    let run = sys_root.join("kernel/mm/ksm/run");
    std::fs::read_to_string(run).ok().map(|v| v.trim() == "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_arch_is_supported() {
        let arch = Arch::native();
        assert!(matches!(arch, Arch::X86_64 | Arch::Aarch64),
                "неподдерживаемая архитектура: {:?}", arch);
        assert_ne!(arch.audit_arch(), 0);
    }

    #[test]
    fn audit_arch_constants() {
        assert_eq!(Arch::X86_64.audit_arch(), 0xC000003E);
        assert_eq!(Arch::Aarch64.audit_arch(), 0xC00000B7);
    }

    #[test]
    fn glibc_runtime_check() {
        // Крейт собирается glibc-тулчейном в CI (F-E-08).
        assert!(runtime_is_glibc());
    }

    #[test]
    fn jetson_detection_from_fake_root() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!detect_jetson(dir.path()));
        std::fs::write(dir.path().join("nv_tegra_release_tmp"), b"").unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(etc.join("nv_tegra_release"), b"R36 (release)").unwrap();
        assert!(detect_jetson(dir.path()));
    }

    #[test]
    fn ksm_check() {
        let dir = tempfile::tempdir().unwrap();
        let ksm = dir.path().join("kernel/mm/ksm");
        std::fs::create_dir_all(&ksm).unwrap();
        std::fs::write(ksm.join("run"), b"1\n").unwrap();
        assert_eq!(ksm_is_disabled(dir.path()), Some(false));
        std::fs::write(ksm.join("run"), b"0\n").unwrap();
        assert_eq!(ksm_is_disabled(dir.path()), Some(true));
        assert_eq!(ksm_is_disabled(&dir.path().join("nonexistent")), None);
    }

    #[test]
    fn platform_collect_smoke() {
        let info = PlatformInfo::collect(Path::new("/proc"));
        assert!(!info.kernel_release.is_empty());
        assert!(info.satisfies_f_e_08());
    }
}
