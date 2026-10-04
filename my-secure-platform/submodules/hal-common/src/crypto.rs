//! Криптографический профиль ZT-AI-CORE (Приложение Б ТЗ, F-H-01…F-H-03).

use std::sync::atomic::{AtomicU64, Ordering};

/// Алгоритм из разрешённого набора профиля.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Данные at-rest; nonce — уникальные 96-битные (F-H-01).
    Aes256Gcm,
    /// Замена AES-256-GCM при невозможности гарантии уникальности nonce.
    Aes256GcmSiv,
    /// Подпись: артефакты, чекпоинты WORM, обновления (F-H-02).
    Ed25519,
    /// ECDH / TLS 1.3 key exchange (F-H-02).
    X25519,
    /// Хеширование WORM-цепочки и артефактов (F-G-02).
    Blake3,
    /// Измерение целостности: IMA, SBOM, Merkle-root весов (F-E-06).
    Sha256,
}

/// Запрещённые конструкции (docs/06-crypto-profile.md §6).
pub const FORBIDDEN_ALGORITHMS: &[&str] = &[
    "GOST-28147",       // «Кузнечик»/«Магма» исключены Разделом 0 ТЗ
    "Kuznyechik",
    "Magma",
    "Streebog",
    "TLS_RSA_KEY_EXCHANGE",
    "TLS_CBC",
    "SHA1_SIGNATURE",
    "MD5",
    "RC4",
    "DES",
    "3DES",
];

/// Шифр-наборы TLS 1.3 (Приложение Б п.1).
pub const TLS13_CIPHERSUITES: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];

/// Профиль: источник истины для валидации крипто-операций в L3/L4/L7.
#[derive(Debug, Clone)]
pub struct CryptoProfile {
    pub spec_version: &'static str,
    pub transit_tls_min: &'static str,
    pub transit_ciphersuites: &'static [&'static str],
    pub at_rest: Algorithm,
    pub at_rest_fallback: Algorithm,
    pub signature: Algorithm,
    pub kex: Algorithm,
    pub worm_hash: Algorithm,
    pub integrity_hash: Algorithm,
    pub random_source: &'static str,
}

impl Default for CryptoProfile {
    fn default() -> Self {
        Self {
            spec_version: crate::SPEC_VERSION,
            transit_tls_min: "1.3",
            transit_ciphersuites: TLS13_CIPHERSUITES,
            at_rest: Algorithm::Aes256Gcm,
            at_rest_fallback: Algorithm::Aes256GcmSiv,
            signature: Algorithm::Ed25519,
            kex: Algorithm::X25519,
            worm_hash: Algorithm::Blake3,
            integrity_hash: Algorithm::Sha256,
            random_source: "getrandom(2)/HW-TRNG",
        }
    }
}

impl CryptoProfile {
    /// Валидация имени алгоритма/шифра: разрешённые — true, запрещённые и
    /// неизвестные — false (fail-closed).
    pub fn is_allowed_cipher(&self, name: &str) -> bool {
        self.transit_ciphersuites.iter().any(|s| s.eq_ignore_ascii_case(name))
    }

    pub fn is_forbidden(&self, name: &str) -> bool {
        FORBIDDEN_ALGORITHMS
            .iter()
            .any(|s| s.eq_ignore_ascii_case(name))
    }
}

/// Политика ключей (F-H-03): приватный материал никогда не экспортируется в D8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLocation {
    /// TPM 2.0 / OP-TEE / HSM — операции на месте, экспорт запрещён.
    SecureHardware,
    /// L3 crypto-daemon (PKCS#11) — вне D8.
    CryptoLayer,
    /// Файловый провайдер — ТОЛЬКО dev/CI (помечается в аудите).
    FileDevOnly,
}

impl KeyLocation {
    /// Разрешено ли использование ключа из D8 (нулевое доверие)?
    pub fn exportable_to_d8(self) -> bool {
        false // приватные ключи не покидают L2/L3 ни при какой локации
    }
}

/// Монотонный 96-битный счётчик nonce для AES-256-GCM (F-H-01, Приложение Б п.2).
///
/// Гарантирует уникальность nonce в пределах экземпляра процесса;
/// персистентное продолжение счётчика — через [`MonotonicNonce96::with_base`]
/// (база загружается из TPM NV / WAL при старте).
#[derive(Debug)]
pub struct MonotonicNonce96 {
    hi: AtomicU64, // старшие 32 бита (эпоха/база)
    lo: AtomicU64, // младшие 64 бита (монотонный счётчик)
}

impl MonotonicNonce96 {
    pub fn new() -> Self {
        Self::with_base(0)
    }

    /// База — значение, сохранённое при прошлом завершении (+запас).
    pub fn with_base(base_hi: u32) -> Self {
        Self {
            hi: AtomicU64::new(base_hi as u64),
            lo: AtomicU64::new(0),
        }
    }

    /// Следующий уникальный 96-битный nonce (12 байт, big-endian).
    pub fn next(&self) -> [u8; 12] {
        let lo = self.lo.fetch_add(1, Ordering::Relaxed);
        if lo == u64::MAX {
            // переполнение младшего слова — поднимаем эпоху (требуется
            // персистентная фиксация до продолжения; в prod — TPM NV).
            self.hi.fetch_add(1, Ordering::SeqCst);
            self.lo.store(0, Ordering::SeqCst);
        }
        let hi = self.hi.load(Ordering::SeqCst) as u32;
        let lo = if lo == u64::MAX { 0 } else { lo };
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&hi.to_be_bytes());
        out[4..].copy_from_slice(&lo.to_be_bytes());
        out
    }
}

impl Default for MonotonicNonce96 {
    fn default() -> Self {
        Self::new()
    }
}

/// BLAKE3-хэш (hex) — единая точка хэширования для всех подсистем (F-G-02).
pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn profile_allows_only_spec_ciphersuites() {
        let p = CryptoProfile::default();
        assert!(p.is_allowed_cipher("TLS_AES_256_GCM_SHA384"));
        assert!(p.is_allowed_cipher("TLS_CHACHA20_POLY1305_SHA256"));
        assert!(!p.is_allowed_cipher("TLS_AES_128_GCM_SHA256"));
        assert!(!p.is_allowed_cipher("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"));
    }

    #[test]
    fn profile_forbids_gost_and_legacy() {
        let p = CryptoProfile::default();
        for bad in ["Kuznyechik", "Magma", "Streebog", "MD5", "RC4", "3DES"] {
            assert!(p.is_forbidden(bad), "{bad} обязан быть запрещён");
        }
        assert!(!p.is_forbidden("AES-256-GCM"));
    }

    #[test]
    fn keys_never_exportable_to_d8() {
        for loc in [
            KeyLocation::SecureHardware,
            KeyLocation::CryptoLayer,
            KeyLocation::FileDevOnly,
        ] {
            assert!(!loc.exportable_to_d8());
        }
    }

    #[test]
    fn nonce96_unique_and_monotonic() {
        let n = MonotonicNonce96::new();
        let mut seen = HashSet::new();
        for _ in 0..100_000 {
            assert!(seen.insert(n.next()));
        }
        let a = n.next();
        let b = n.next();
        assert!(a < b, "nonce обязан расти big-endian лексикографически");
    }

    #[test]
    fn nonce96_base_continues() {
        let n1 = MonotonicNonce96::with_base(7);
        let n2 = MonotonicNonce96::with_base(8);
        assert!(n1.next() < n2.next());
    }

    #[test]
    fn blake3_known_vector() {
        // Официальный тест-вектор BLAKE3: пустой ввод.
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        // Вектор для "abc" (BLAKE3 test vectors, input_len=3).
        assert_eq!(
            blake3_hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }
}
