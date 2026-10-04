//! Клиент WORM-шины (L7): публикация FSM_EVENT в worm-audit по UDS.
//!
//! Контракт полей — audit.proto (AppendRequest/AuditResponse); транспорт
//! dev-контура — line-oriented JSON поверх AF_UNIX. Отказ шины НЕ блокирует
//! FSM (best-effort с коротким таймаутом): локальный WAL остаётся источником
//! истины, события дополняются через спул (runbook §5).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::engine::StateEvent;

/// Клиент аудита: один экземпляр на движок, ленивое переподключение.
pub struct AuditClient {
    socket_path: String,
    timeout: Duration,
    stream: Option<UnixStream>,
}

impl AuditClient {
    pub fn new(socket_path: impl AsRef<Path>, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_string_lossy().into_owned(),
            timeout,
            stream: None,
        }
    }

    fn connect(&mut self) -> std::io::Result<&mut UnixStream> {
        if self.stream.is_none() {
            let s = UnixStream::connect(&self.socket_path)?;
            s.set_read_timeout(Some(self.timeout))?;
            s.set_write_timeout(Some(self.timeout))?;
            self.stream = Some(s);
        }
        Ok(self.stream.as_mut().expect("stream just set"))
    }

    /// Отправить Append-запрос (kind = RECORD_KIND_FSM_EVENT).
    pub fn append_fsm_event(&mut self, event: &StateEvent) -> std::io::Result<u64> {
        let payload = serde_json::to_vec(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        use base64_lite::encode;
        let req = serde_json::json!({
            "jsonrpc": "zt-uds/1.0",
            "method": "Append",
            "params": {
                "kind": "RECORD_KIND_FSM_EVENT",
                "source": "fsm-engine",
                "subject": format!("epoch-{}", event.current.epoch),
                "payload_b64": encode(&payload),
            },
            "id": event.timestamp_unix_ns,
        });
        let line = serde_json::to_string(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let stream = match self.connect() {
            Ok(s) => s,
            Err(e) => {
                self.stream = None;
                return Err(e);
            }
        };
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(s) => s,
            Err(e) => return Err(e),
        });
        let mut resp = String::new();
        if reader.read_line(&mut resp)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "audit closed",
            ));
        }
        let value: serde_json::Value = serde_json::from_str(resp.trim()).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err.to_string()));
        }
        Ok(value
            .pointer("/result/seq")
            .and_then(|v| v.as_u64())
            .unwrap_or(0))
    }
}

/// Минимальный base64 (стандартный алфавит, с padding) — без внешних зависимостей.
pub mod base64_lite {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(n >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[n as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    pub fn decode(text: &str) -> Result<Vec<u8>, String> {
        let bytes: Vec<u8> = text
            .bytes()
            .filter(|b| *b != b'\n' && *b != b'\r')
            .collect();
        if bytes.len() % 4 != 0 {
            return Err("bad base64 length".into());
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        for chunk in bytes.chunks(4) {
            let mut n = 0u32;
            let mut pad = 0;
            for (i, c) in chunk.iter().enumerate() {
                let v = if *c == b'=' {
                    pad += 1;
                    0
                } else {
                    match ALPHABET.iter().position(|a| a == c) {
                        Some(p) => p as u32,
                        None => return Err(format!("bad base64 char at {i}")),
                    }
                };
                n = (n << 6) | v;
            }
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::base64_lite::{decode, encode};

    #[test]
    fn base64_roundtrip_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        let cases: [&[u8]; 6] = [
            b"", b"f", b"fo", b"foo", b"hello world", b"\x00\x01\xfe\xff",
        ];
        for s in cases {
            assert_eq!(decode(&encode(s)).unwrap(), s.to_vec());
        }
    }
}
