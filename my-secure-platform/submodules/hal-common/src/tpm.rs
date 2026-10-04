//! Операции TPM 2.0 / HSM (F-H-03, F-H-05, F-G-04/05, F-I-02).
//!
//! [`TpmOps`] — контракт Root of Trust:
//! * NV-Counter — якорь WORM (anti-truncation) и anti-downgrade обновлений;
//! * PCR[0-15] — измерение загрузки (0-7) и рантайма ZT-AI-CORE (8-15);
//! * Quote — Remote Attestation для LLM Gateway (AK-подпись PCR);
//! * sign_ed25519 — подпись чекпоинтов WORM без экспорта ключа.
//!
//! [`MockTpm`] — файловая детерминированная реализация для CI/стендов:
//! монотонные NV-счётчики переживают перезапуск процесса (критично для
//! тестов anti-truncation), симуляция износа NV-ячейки, PCR-extend по
//! SHA-256, подпись Ed25519 ключом из фиксированного seed.
//! Продакшен-реализация (tss2 / tpm2-tools / PKCS#11 HSM) подключается
//! на целевом железе и реализует тот же trait.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Индексы PCR рантайма ZT-AI-CORE (F-H-05: PCR[8-15]).
pub const PCR_RUNTIME_RANGE: std::ops::RangeInclusive<u32> = 8..=15;
/// Индексы PCR firmware/bootloader/kernel/initrd (PCR[0-7]).
pub const PCR_BOOT_RANGE: std::ops::RangeInclusive<u32> = 0..=7;

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("tpm nv index {0} not found")]
    NvIndexNotFound(u32),
    #[error("tpm nv write failed: {0}")]
    NvWriteFailed(String),
    #[error("tpm nv counter would overflow")]
    NvOverflow,
    #[error("pcr index out of range 0..=23: {0}")]
    BadPcrIndex(u32),
    #[error("tpm unavailable: {0}")]
    Unavailable(String),
    #[error("signing key handle unknown: {0}")]
    BadKeyHandle(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// TPM Quote: AK-подпись выбранных PCR (F-H-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmQuote {
    pub pcr_selection: Vec<u32>,
    pub pcr_digests: Vec<[u8; 32]>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Контракт Root of Trust (L2).
pub trait TpmOps {
    /// Прочитать NV-счётчик (anti-truncation якорь / version_number).
    fn nv_read(&mut self, index: u32) -> Result<u64, TpmError>;
    /// Записать NV-счётчик монотонно (только вперёд; откат = ошибка).
    /// Включает учёт износа ячейки (F-G-05).
    fn nv_write_monotonic(&mut self, index: u32, value: u64) -> Result<(), TpmError>;
    /// Инкрементировать NV-счётчик.
    fn nv_increment(&mut self, index: u32) -> Result<u64, TpmError>;
    /// Износ NV-ячейки, % (0.0–100.0); порог алерта — 80% (F-G-05).
    fn nv_wear_percent(&mut self, index: u32) -> Result<f64, TpmError>;
    /// PCR extend: PCR = SHA256(PCR_old || digest).
    fn pcr_extend(&mut self, index: u32, digest: &[u8; 32]) -> Result<(), TpmError>;
    /// Прочитать текущее значение PCR.
    fn pcr_read(&mut self, index: u32) -> Result<[u8; 32], TpmError>;
    /// Quote: AK-подпись набора PCR с nonce вызывающей стороны.
    fn quote(&mut self, pcrs: &[u32], nonce: &[u8]) -> Result<TpmQuote, TpmError>;
    /// Подписать дайджест Ed25519-ключом, не покидающим TPM (F-H-03).
    fn sign_ed25519(&mut self, key_handle: &str, message: &[u8])
        -> Result<[u8; 64], TpmError>;
    /// Публичная часть ключа подписи (для верификации вовне).
    fn verifying_key(&mut self, key_handle: &str) -> Result<[u8; 32], TpmError>;
    /// Доступен ли TPM сейчас.
    fn available(&self) -> bool;
}

/// Ресурс записи NV-ячейки (для симуляции износа в mock).
pub const MOCK_NV_ENDURANCE_WRITES: u64 = 100;

/// Детерминированный seed AK для стендов (НЕ секрет в prod — там ключ в TPM).
const MOCK_AK_SEED: [u8; 32] = *b"zt-ai-core-mock-ak-seed-00000001";

/// Файловая mock-реализация TPM: состояние в каталоге (переживает рестарт).
#[derive(Debug)]
pub struct MockTpm {
    root: PathBuf,
    online: bool,
    ak: SigningKey,
}

impl MockTpm {
    /// Создать/открыть mock-TPM с состоянием в `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, TpmError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            online: true,
            ak: SigningKey::from_bytes(&MOCK_AK_SEED),
        })
    }

    /// Эмуляция отказа TPM (chaos-сценарий C: NV write failure).
    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }

    fn nv_path(&self, index: u32) -> PathBuf {
        self.root.join(format!("nv_{index:08x}"))
    }

    fn wear_path(&self, index: u32) -> PathBuf {
        self.root.join(format!("nv_{index:08x}.wear"))
    }

    fn pcr_path(&self, index: u32) -> PathBuf {
        self.root.join(format!("pcr_{index:02}"))
    }

    fn read_u64_file(path: &Path) -> Result<u64, TpmError> {
        match std::fs::read_to_string(path) {
            Ok(text) => text
                .trim()
                .parse::<u64>()
                .map_err(|e| TpmError::NvWriteFailed(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(TpmError::Io(e)),
        }
    }

    fn write_u64_file(path: &Path, value: u64) -> Result<(), TpmError> {
        // атомарная запись: tmp + rename (аналог гарантированного fsync в WAL)
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, value.to_string().as_bytes())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    fn bump_wear(&self, index: u32) -> Result<(), TpmError> {
        let writes = Self::read_u64_file(&self.wear_path(index))? + 1;
        Self::write_u64_file(&self.wear_path(index), writes)
    }
}

impl TpmOps for MockTpm {
    fn nv_read(&mut self, index: u32) -> Result<u64, TpmError> {
        if !self.online {
            return Err(TpmError::Unavailable("mock tpm offline".into()));
        }
        Self::read_u64_file(&self.nv_path(index))
    }

    fn nv_write_monotonic(&mut self, index: u32, value: u64) -> Result<(), TpmError> {
        if !self.online {
            return Err(TpmError::Unavailable("mock tpm offline".into()));
        }
        let current = Self::read_u64_file(&self.nv_path(index))?;
        if value < current {
            return Err(TpmError::NvWriteFailed(format!(
                "non-monotonic write: {value} < {current} (anti-downgrade)"
            )));
        }
        if value == u64::MAX {
            return Err(TpmError::NvOverflow);
        }
        Self::write_u64_file(&self.nv_path(index), value)?;
        self.bump_wear(index)
    }

    fn nv_increment(&mut self, index: u32) -> Result<u64, TpmError> {
        let current = self.nv_read(index)?;
        let next = current.checked_add(1).ok_or(TpmError::NvOverflow)?;
        self.nv_write_monotonic(index, next)?;
        Ok(next)
    }

    fn nv_wear_percent(&mut self, index: u32) -> Result<f64, TpmError> {
        let writes = Self::read_u64_file(&self.wear_path(index))?;
        Ok((writes as f64) / (MOCK_NV_ENDURANCE_WRITES as f64) * 100.0)
    }

    fn pcr_extend(&mut self, index: u32, digest: &[u8; 32]) -> Result<(), TpmError> {
        if !PCR_BOOT_RANGE.contains(&index) && !PCR_RUNTIME_RANGE.contains(&index)
            && index > 23
        {
            return Err(TpmError::BadPcrIndex(index));
        }
        if !self.online {
            return Err(TpmError::Unavailable("mock tpm offline".into()));
        }
        let old = self.pcr_read(index)?;
        let mut hasher = Sha256::new();
        hasher.update(old);
        hasher.update(digest);
        let new: [u8; 32] = hasher.finalize().into();
        std::fs::write(self.pcr_path(index), hex::encode(new))?;
        Ok(())
    }

    fn pcr_read(&mut self, index: u32) -> Result<[u8; 32], TpmError> {
        if index > 23 {
            return Err(TpmError::BadPcrIndex(index));
        }
        match std::fs::read_to_string(self.pcr_path(index)) {
            Ok(text) => {
                let bytes = hex::decode(text.trim())
                    .map_err(|e| TpmError::NvWriteFailed(e.to_string()))?;
                if bytes.len() != 32 {
                    return Err(TpmError::NvWriteFailed("bad pcr length".into()));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(out)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok([0u8; 32]),
            Err(e) => Err(TpmError::Io(e)),
        }
    }

    fn quote(&mut self, pcrs: &[u32], nonce: &[u8]) -> Result<TpmQuote, TpmError> {
        if !self.online {
            return Err(TpmError::Unavailable("mock tpm offline".into()));
        }
        let mut digests = Vec::with_capacity(pcrs.len());
        for idx in pcrs {
            digests.push(self.pcr_read(*idx)?);
        }
        let mut to_sign = Vec::new();
        for (idx, d) in pcrs.iter().zip(digests.iter()) {
            to_sign.extend_from_slice(&idx.to_be_bytes());
            to_sign.extend_from_slice(d);
        }
        to_sign.extend_from_slice(nonce);
        let sig: Signature = self.ak.sign(&to_sign);
        Ok(TpmQuote {
            pcr_selection: pcrs.to_vec(),
            pcr_digests: digests,
            nonce: nonce.to_vec(),
            signature: sig.to_bytes().to_vec(),
        })
    }

    fn sign_ed25519(
        &mut self,
        key_handle: &str,
        message: &[u8],
    ) -> Result<[u8; 64], TpmError> {
        if key_handle != "ak-default" {
            return Err(TpmError::BadKeyHandle(key_handle.to_string()));
        }
        if !self.online {
            return Err(TpmError::Unavailable("mock tpm offline".into()));
        }
        let sig: Signature = self.ak.sign(message);
        Ok(sig.to_bytes())
    }

    fn verifying_key(&mut self, key_handle: &str) -> Result<[u8; 32], TpmError> {
        if key_handle != "ak-default" {
            return Err(TpmError::BadKeyHandle(key_handle.to_string()));
        }
        let vk: VerifyingKey = self.ak.verifying_key();
        Ok(vk.to_bytes())
    }

    fn available(&self) -> bool {
        self.online
    }
}

/// Верификация Quote публичным ключом AK (сторона внешнего сервиса, F-H-05).
pub fn verify_quote(quote: &TpmQuote, ak_public: &[u8; 32]) -> Result<bool, TpmError> {
    let vk = VerifyingKey::from_bytes(ak_public)
        .map_err(|e| TpmError::Unavailable(e.to_string()))?;
    let mut to_verify = Vec::new();
    for (idx, d) in quote.pcr_selection.iter().zip(quote.pcr_digests.iter()) {
        to_verify.extend_from_slice(&idx.to_be_bytes());
        to_verify.extend_from_slice(d);
    }
    to_verify.extend_from_slice(&quote.nonce);
    if to_verify.len() != quote.pcr_selection.len() * 36 + quote.nonce.len() {
        return Ok(false);
    }
    let mut sig_bytes = [0u8; 64];
    if quote.signature.len() != 64 {
        return Ok(false);
    }
    sig_bytes.copy_from_slice(&quote.signature);
    let sig = Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    Ok(vk.verify(&to_verify, &sig).is_ok())
}

/// Сверка PCR Quote с эталоном SBOM (F-H-05): ожидаемые значения PCR.
pub fn pcr_matches_reference(quote: &TpmQuote, expected: &BTreeMap<u32, [u8; 32]>) -> bool {
    quote
        .pcr_selection
        .iter()
        .zip(quote.pcr_digests.iter())
        .all(|(idx, digest)| expected.get(idx).map(|e| e == digest).unwrap_or(false))
}

/// Минимальный hex-кодер/декодер (без внешних зависимостей).
pub(crate) mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd hex length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("bad hex at {i}: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() -> (tempfile::TempDir, MockTpm) {
        let dir = tempfile::tempdir().unwrap();
        let tpm = MockTpm::open(dir.path()).unwrap();
        (dir, tpm)
    }

    #[test]
    fn nv_counter_monotonic_and_persistent() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut tpm = MockTpm::open(dir.path()).unwrap();
            assert_eq!(tpm.nv_read(1).unwrap(), 0);
            assert_eq!(tpm.nv_increment(1).unwrap(), 1);
            assert_eq!(tpm.nv_increment(1).unwrap(), 2);
            assert!(tpm.nv_write_monotonic(1, 1).is_err()); // откат запрещён
            tpm.nv_write_monotonic(1, 10).unwrap();
        }
        // состояние пережило перезапуск
        let mut tpm = MockTpm::open(dir.path()).unwrap();
        assert_eq!(tpm.nv_read(1).unwrap(), 10);
    }

    #[test]
    fn nv_wear_tracking_and_threshold() {
        let (_d, mut tpm) = mock();
        for i in 0..80u64 {
            tpm.nv_write_monotonic(2, i + 1).unwrap();
        }
        let wear = tpm.nv_wear_percent(2).unwrap();
        assert!((wear - 80.0).abs() < 0.001, "wear={wear}");
        assert!(wear >= 80.0, "порог алерта F-G-05 достигнут");
    }

    #[test]
    fn pcr_extend_semantics() {
        let (_d, mut tpm) = mock();
        assert_eq!(tpm.pcr_read(8).unwrap(), [0u8; 32]);
        let d1 = Sha256::digest(b"zt-binary").into();
        tpm.pcr_extend(8, &d1).unwrap();
        let mut expect = Sha256::new();
        expect.update([0u8; 32]);
        expect.update(d1);
        let expect: [u8; 32] = expect.finalize().into();
        assert_eq!(tpm.pcr_read(8).unwrap(), expect);
        assert!(tpm.pcr_extend(24, &[0u8; 32]).is_err());
    }

    #[test]
    fn quote_roundtrip_verification() {
        let (_d, mut tpm) = mock();
        tpm.pcr_extend(8, &Sha256::digest(b"runtime").into()).unwrap();
        let nonce = b"gateway-challenge-01";
        let quote = tpm.quote(&[0, 1, 8], nonce).unwrap();
        let vk = tpm.verifying_key("ak-default").unwrap();
        assert!(verify_quote(&quote, &vk).unwrap());
        // подмена digest → верификация падает
        let mut tampered = quote.clone();
        tampered.pcr_digests[2][0] ^= 0xFF;
        assert!(!verify_quote(&tampered, &vk).unwrap());
        // подмена nonce → падает
        let mut t2 = quote.clone();
        t2.nonce = b"other".to_vec();
        assert!(!verify_quote(&t2, &vk).unwrap());
    }

    #[test]
    fn pcr_reference_match() {
        let (_d, mut tpm) = mock();
        let d = Sha256::digest(b"sbom-runtime").into();
        tpm.pcr_extend(9, &d).unwrap();
        let quote = tpm.quote(&[9], b"n").unwrap();
        let mut reference = BTreeMap::new();
        let mut expect = Sha256::new();
        expect.update([0u8; 32]);
        expect.update(d);
        reference.insert(9u32, <[u8; 32]>::from(expect.finalize()));
        assert!(pcr_matches_reference(&quote, &reference));
        reference.insert(9, [7u8; 32]);
        assert!(!pcr_matches_reference(&quote, &reference));
    }

    #[test]
    fn signing_without_key_export() {
        let (_d, mut tpm) = mock();
        let msg = b"checkpoint-hash";
        let sig = tpm.sign_ed25519("ak-default", msg).unwrap();
        let vk_bytes = tpm.verifying_key("ak-default").unwrap();
        let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        use ed25519_dalek::Verifier;
        vk.verify(msg, &Signature::from_bytes(&sig)).unwrap();
        assert!(tpm.sign_ed25519("nonexistent", msg).is_err());
    }

    #[test]
    fn offline_tpm_reports_unavailable() {
        let (_d, mut tpm) = mock();
        tpm.set_online(false);
        assert!(!tpm.available());
        assert!(matches!(tpm.nv_read(1), Err(TpmError::Unavailable(_))));
        assert!(tpm.sign_ed25519("ak-default", b"x").is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 15, 16, 255];
        let s = hex::encode(bytes);
        assert_eq!(s, "00010f10ff");
        assert_eq!(hex::decode(&s).unwrap(), bytes);
        assert!(hex::decode("0").is_err());
        assert!(hex::decode("zz").is_err());
    }
}
