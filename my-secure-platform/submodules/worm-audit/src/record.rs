//! Запись WORM-журнала и BLAKE3 hash-chain (F-G-01/02, Приложение Б п.3).
//!
//! ```text
//! chain_hash_i = BLAKE3( previous_hash ‖ payload_hash ‖ timestamp ‖ nonce )
//! ```
//! где `timestamp` — u64 big-endian unix-nanoseconds, `nonce` — 16 байт
//! getrandom(). Genesis: `previous_hash = 32 × 0x00`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Типы событий (audit.proto:RecordKind; NF-09 — 100% покрытие).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordKind {
    Unspecified,
    Prompt,
    Response,
    Egress,
    Ipc,
    Operator,
    FsmEvent,
    Integrity,
    ValidatorVerdict,
    SeccompViolation,
    Bootstrap,
    Attestation,
}

impl RecordKind {
    pub fn parse(s: &str) -> Self {
        let norm = s.to_ascii_uppercase().replace("RECORD_KIND_", "");
        match norm.as_str() {
            "PROMPT" => RecordKind::Prompt,
            "RESPONSE" => RecordKind::Response,
            "EGRESS" => RecordKind::Egress,
            "IPC" => RecordKind::Ipc,
            "OPERATOR" => RecordKind::Operator,
            "FSM_EVENT" => RecordKind::FsmEvent,
            "INTEGRITY" => RecordKind::Integrity,
            "VALIDATOR_VERDICT" => RecordKind::ValidatorVerdict,
            "SECCOMP_VIOLATION" => RecordKind::SeccompViolation,
            "BOOTSTRAP" => RecordKind::Bootstrap,
            "ATTESTATION" => RecordKind::Attestation,
            _ => RecordKind::Unspecified,
        }
    }
}

/// Полная запись цепочки (audit.proto:AuditRecord).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    #[serde(with = "hex32")]
    pub payload_hash: [u8; 32],
    pub timestamp_unix_ns: i64,
    #[serde(with = "hex16")]
    pub nonce: [u8; 16],
    #[serde(with = "hex32")]
    pub previous_hash: [u8; 32],
    #[serde(with = "hex64")]
    pub record_signature: [u8; 64],
    #[serde(with = "hex32")]
    pub chain_hash: [u8; 32],
    pub kind: RecordKind,
    pub source: String,
    pub subject: String,
}

/// BLAKE3(prev ‖ payload_hash ‖ ts_be ‖ nonce) — Приложение Б п.3.
pub fn chain_hash(
    previous_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    timestamp_unix_ns: i64,
    nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(previous_hash);
    hasher.update(payload_hash);
    hasher.update(&(timestamp_unix_ns as u64).to_be_bytes());
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 от payload.
pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

/// Криптостойкий nonce 16 байт — ТОЛЬКО getrandom(2) (Приложение Б п.4).
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    // getrandom через libc (glibc-обёртка недоступна напрямую в std).
    let rc = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            nonce.as_mut_ptr() as *mut libc::c_void,
            nonce.len(),
            0u32,
        )
    };
    if rc != nonce.len() as libc::c_long {
        // Fallback невозможен по политике: случайность только getrandom().
        panic!(
            "getrandom(2) failed (rc={rc}): генерация nonce обязательна через getrandom \
             (Приложение Б п.4)"
        );
    }
    nonce
}

/// Текущее время в unix-наносекундах.
pub fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Genesis-хэш цепочки (32 нуля).
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err(format!("hex length {} != {}", s.len(), N * 2));
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex at {i}: {e}"))?;
    }
    Ok(out)
}

// --- serde-адаптеры hex-полей -------------------------------------------------

mod hex32 {
    use super::{hex_decode, hex_encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        hex_decode(&text).map_err(serde::de::Error::custom)
    }
}

mod hex16 {
    use super::{hex_decode, hex_encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let text = String::deserialize(d)?;
        hex_decode(&text).map_err(serde::de::Error::custom)
    }
}

mod hex64 {
    use super::{hex_decode, hex_encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let text = String::deserialize(d)?;
        hex_decode(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_hash_matches_appendix_b_construction() {
        let prev = [7u8; 32];
        let ph = payload_hash(b"prompt-text");
        let ts: i64 = 1_700_000_000_000_000_000;
        let nonce = [3u8; 16];
        let got = chain_hash(&prev, &ph, ts, &nonce);
        // независимая ручная конкатенация
        let mut buf = Vec::new();
        buf.extend_from_slice(&prev);
        buf.extend_from_slice(&ph);
        buf.extend_from_slice(&(ts as u64).to_be_bytes());
        buf.extend_from_slice(&nonce);
        assert_eq!(got, *blake3::hash(&buf).as_bytes());
    }

    #[test]
    fn chain_hash_is_order_sensitive() {
        let a = chain_hash(&[1; 32], &[2; 32], 100, &[3; 16]);
        let b = chain_hash(&[2; 32], &[1; 32], 100, &[3; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn payload_hash_known_vector() {
        // BLAKE3("") — официальный вектор
        assert_eq!(
            hex_encode(&payload_hash(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn nonce_unique_from_getrandom() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(generate_nonce()));
        }
    }

    #[test]
    fn record_jsonl_roundtrip() {
        let rec = AuditRecord {
            seq: 42,
            payload_hash: payload_hash(b"x"),
            timestamp_unix_ns: now_unix_ns(),
            nonce: generate_nonce(),
            previous_hash: GENESIS_HASH,
            record_signature: [9u8; 64],
            chain_hash: [8u8; 32],
            kind: RecordKind::Prompt,
            source: "rag-core".into(),
            subject: "d8".into(),
        };
        let line = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(rec, back);
        assert!(line.contains("\"PROMPT\""));
        assert!(line.contains(&hex_encode(&rec.payload_hash)));
    }

    #[test]
    fn kind_parse_wire_names() {
        assert_eq!(RecordKind::parse("RECORD_KIND_EGRESS"), RecordKind::Egress);
        assert_eq!(RecordKind::parse("PROMPT"), RecordKind::Prompt);
        assert_eq!(RecordKind::parse("???"), RecordKind::Unspecified);
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0xAB; 32];
        assert_eq!(hex_decode::<32>(&hex_encode(&bytes)).unwrap(), bytes);
        assert!(hex_decode::<32>("ff").is_err());
    }
}
