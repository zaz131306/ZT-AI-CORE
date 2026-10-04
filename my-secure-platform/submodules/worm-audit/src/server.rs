//! UDS-сервер контракта `audit.proto` (line-oriented JSON dev-транспорт).
//!
//! Методы: Append, GetRecord, VerifyChain, GetLatestCheckpoint,
//! PublishCheckpoint, GetAnchorStatus, Reconcile, GetStats, IngestSpool,
//! Healthcheck. Все соединения проходят SO_PEERCRED (F-E-04).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::anchors::DirectoryAnchor;
use crate::record::{hex_encode, RecordKind};
use crate::service::AuditService;

type Service = AuditService<zt_hal_common::tpm::MockTpm, DirectoryAnchor>;

pub struct ServerContext {
    pub service: Mutex<Service>,
    pub running: AtomicBool,
    pub started_at: Instant,
    pub reconcile_report: Mutex<Option<Value>>,
}

impl ServerContext {
    pub fn new(service: Service, reconcile_report: Option<Value>) -> Arc<Self> {
        Arc::new(Self {
            service: Mutex::new(service),
            running: AtomicBool::new(true),
            started_at: Instant::now(),
            reconcile_report: Mutex::new(reconcile_report),
        })
    }

    fn service(&self) -> Result<MutexGuard<'_, Service>, String> {
        self.service.lock().map_err(|e| format!("service lock poisoned: {e}"))
    }

    pub fn handle_request(&self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));
        match self.dispatch(method, &params) {
            Ok(result) => json!({"jsonrpc": "zt-uds/1.0", "id": id, "result": result}),
            Err(err) => json!({"jsonrpc": "zt-uds/1.0", "id": id, "error": err}),
        }
    }

    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, String> {
        match method {
            "Append" => {
                let payload = decode_payload(params)?;
                let kind = RecordKind::parse(
                    params.get("kind").and_then(|v| v.as_str()).unwrap_or("UNSPECIFIED"),
                );
                let source = params.get("source").and_then(|v| v.as_str()).unwrap_or("unknown");
                let subject = params.get("subject").and_then(|v| v.as_str()).unwrap_or("");
                let nonce = match params.get("nonce_b64").and_then(|v| v.as_str()) {
                    Some(b64) => {
                        let bytes = base64_decode(b64)?;
                        if bytes.len() != 16 {
                            return Err("nonce must be 16 bytes".into());
                        }
                        let mut n = [0u8; 16];
                        n.copy_from_slice(&bytes);
                        Some(n)
                    }
                    None => None,
                };
                let ts = params.get("timestamp_unix_ns").and_then(|v| v.as_i64());
                let mut svc = self.service()?;
                if nonce.is_some() || ts.is_some() {
                    let rec = svc
                        .chain_mut()
                        .append(&payload, kind, source, subject, nonce, ts)
                        .map_err(|e| e.to_string())?;
                    Ok(record_json(&rec))
                } else {
                    let rec = svc.append(&payload, kind, source, subject).map_err(|e| e.to_string())?;
                    Ok(record_json(&rec))
                }
            }
            "GetRecord" => {
                let seq = params.get("seq").and_then(|v| v.as_u64()).ok_or("seq required")?;
                let svc = self.service()?;
                for item in crate::chain::ChainIter::open(svc.chain().path()).map_err(|e| e.to_string())? {
                    let rec = item.map_err(|e| e.to_string())?;
                    if rec.seq == seq {
                        return Ok(record_json(&rec));
                    }
                    if rec.seq > seq {
                        break;
                    }
                }
                Err(format!("record seq={seq} not found"))
            }
            "VerifyChain" => {
                let deep = params.get("deep").and_then(|v| v.as_bool()).unwrap_or(true);
                let sigs = params
                    .get("verify_signatures")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let from = params.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let to = params.get("to_seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let svc = self.service()?;
                let report = svc.verify(deep, sigs, from, to);
                serde_json::to_value(report).map_err(|e| e.to_string())
            }
            "GetLatestCheckpoint" => {
                let svc = self.service()?;
                match svc.last_checkpoint() {
                    Some(cp) => serde_json::to_value(cp).map_err(|e| e.to_string()),
                    None => Ok(json!({"published": false})),
                }
            }
            "PublishCheckpoint" => {
                let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
                let anchor_tpm = params.get("anchor_tpm").and_then(|v| v.as_bool()).unwrap_or(true);
                let anchor_ext = params.get("anchor_ext").and_then(|v| v.as_bool()).unwrap_or(true);
                let mut svc = self.service()?;
                let outcome = svc
                    .publish_checkpoint(force, anchor_tpm, anchor_ext)
                    .map_err(|e| e.to_string())?;
                serde_json::to_value(&outcome).map_err(|e| e.to_string())
            }
            "GetAnchorStatus" => {
                let mut svc = self.service()?;
                let status = svc.anchor_status();
                let mut value = serde_json::to_value(&status).map_err(|e| e.to_string())?;
                value["ext_degraded"] = json!(svc.ext_degraded());
                Ok(value)
            }
            "Reconcile" => {
                let mut svc = self.service()?;
                let report = svc.reconcile_at_startup().map_err(|e| e.to_string())?;
                serde_json::to_value(&report).map_err(|e| e.to_string())
            }
            "GetStats" => {
                let svc = self.service()?;
                let stats = svc.stats();
                let mut value = serde_json::to_value(&stats).map_err(|e| e.to_string())?;
                value["sync_policy"] = json!(svc.config().chain.sync_policy.as_str());
                value["next_seq"] = json!(svc.chain().seq());
                Ok(value)
            }
            "IngestSpool" => {
                let path = params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or("path required")?;
                let remove = params.get("remove_after").and_then(|v| v.as_bool()).unwrap_or(false);
                let mut svc = self.service()?;
                let n = svc.ingest_spool(PathBuf::from(path), remove).map_err(|e| e.to_string())?;
                Ok(json!({"ingested": n}))
            }
            "Healthcheck" => {
                let svc = self.service()?;
                let stats = svc.stats();
                Ok(json!({
                    "healthy": true,
                    "total_records": stats.total_records,
                    "write_locked": svc.chain().write_locked(),
                    "uptime_secs": self.started_at.elapsed().as_secs_f64(),
                }))
            }
            other => Err(format!("unknown method: {other}")),
        }
    }
}

fn record_json(rec: &crate::record::AuditRecord) -> Value {
    json!({
        "seq": rec.seq,
        "payload_hash": hex_encode(&rec.payload_hash),
        "timestamp_unix_ns": rec.timestamp_unix_ns,
        "nonce": hex_encode(&rec.nonce),
        "previous_hash": hex_encode(&rec.previous_hash),
        "record_signature": hex_encode(&rec.record_signature),
        "chain_hash": hex_encode(&rec.chain_hash),
        "kind": rec.kind,
        "source": rec.source,
        "subject": rec.subject,
    })
}

fn decode_payload(params: &Value) -> Result<Vec<u8>, String> {
    if let Some(b64) = params.get("payload_b64").and_then(|v| v.as_str()) {
        return base64_decode(b64);
    }
    if let Some(raw) = params.get("payload") {
        return Ok(serde_json::to_vec(raw).map_err(|e| e.to_string())?);
    }
    Err("payload_b64 or payload required".into())
}

fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    // компактный декодер (стандартный алфавит); запросы приходят из доверенных
    // компонентов контура, строгость — на уровне валидации длин ниже по коду
    let bytes: Vec<u8> = text.bytes().filter(|b| *b != b'\n' && *b != b'\r').collect();
    if bytes.len() % 4 != 0 {
        return Err("bad base64 length".into());
    }
    const INV: [i8; 128] = {
        let mut table = [-1i8; 128];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[alphabet[i] as usize] = i as i8;
            i += 1;
        }
        table
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for c in chunk {
            if *c == b'=' {
                pad += 1;
                n <<= 6;
                continue;
            }
            if *c >= 128 {
                return Err("bad base64 char".into());
            }
            let v = INV[*c as usize];
            if v < 0 {
                return Err("bad base64 char".into());
            }
            n = (n << 6) | v as u32;
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

/// Запустить сервер (блокирующий accept-loop).
pub fn serve(ctx: Arc<ServerContext>, socket_path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = socket_path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    set_socket_permissions(&path);
    eprintln!("[zt-worm-audit] serving on {}", path.display());
    for stream in listener.incoming() {
        if !ctx.running.load(Ordering::Relaxed) {
            break;
        }
        match stream {
            Ok(stream) => {
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || handle_connection(ctx, stream));
            }
            Err(e) => eprintln!("[zt-worm-audit] accept error: {e}"),
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn set_socket_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
    }
}

fn handle_connection(ctx: Arc<ServerContext>, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    if let Err(e) = verify_peer(&stream) {
        eprintln!("[zt-worm-audit] peer rejected: {e}");
        return;
    }
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(req) => ctx.handle_request(&req),
            Err(e) => json!({"jsonrpc": "zt-uds/1.0", "error": format!("bad json: {e}")}),
        };
        if writer
            .write_all(serde_json::to_string(&response).unwrap_or_default().as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .and_then(|_| writer.flush())
            .is_err()
        {
            break;
        }
    }
}

/// SO_PEERCRED (F-E-04): uid клиента из allow-list.
fn verify_peer(stream: &UnixStream) -> Result<(i32, u32, u32), String> {
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    use std::os::unix::io::AsRawFd;
    let mut cred = Ucred { pid: 0, uid: u32::MAX, gid: u32::MAX };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            &mut cred as *mut Ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "getsockopt(SO_PEERCRED): {}",
            std::io::Error::last_os_error()
        ));
    }
    let allowed: Vec<u32> = std::env::var("ZT_IPC_ALLOWED_UIDS")
        .unwrap_or_else(|_| "0".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if !allowed.contains(&cred.uid) {
        return Err(format!("uid {} not allowed {allowed:?}", cred.uid));
    }
    Ok((cred.pid, cred.uid, cred.gid))
}

/// Одноразовый клиентский вызов (healthcheck-бинарь, интеграционные тесты).
pub fn call_once(
    socket_path: impl AsRef<Path>,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<Value, String> {
    let stream = UnixStream::connect(socket_path.as_ref()).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let req = json!({
        "jsonrpc": "zt-uds/1.0",
        "method": method,
        "params": params,
        "id": crate::record::now_unix_ns(),
    });
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    writer
        .write_all(serde_json::to_string(&req).unwrap().as_bytes())
        .map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let resp: Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainConfig, SeedSigner, SyncPolicy};
    use crate::checkpoint::CheckpointPolicy;
    use crate::service::ServiceConfig;
    use zt_hal_common::tpm::MockTpm;

    /// Локальный base64-кодер для тестов (стандартный алфавит).
    fn b64(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in data.chunks(3) {
            let n = ((c[0] as u32) << 16)
                | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
                | (c.get(2).copied().unwrap_or(0) as u32);
            out.push(A[((n >> 18) & 63) as usize] as char);
            out.push(A[((n >> 12) & 63) as usize] as char);
            out.push(if c.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
            out.push(if c.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
        }
        out
    }

    fn test_ctx(dir: &tempfile::TempDir) -> Arc<ServerContext> {
        let tpm = MockTpm::open(dir.path().join("tpm")).unwrap();
        let ext = DirectoryAnchor::new(dir.path().join("ext")).unwrap();
        let cfg = ServiceConfig {
            chain: ChainConfig {
                sync_policy: SyncPolicy::OnCheckpoint,
                ..Default::default()
            },
            checkpoint_policy: CheckpointPolicy {
                every_records: 5,
                every_interval: Duration::from_secs(3600),
            },
            tpm_min_interval: Duration::ZERO,
            ..Default::default()
        };
        let signer = Box::new(SeedSigner::from_seed(*b"zt-worm-server-test-seed-0000001"));
        let svc = AuditService::open(
            dir.path().join("chain.jsonl"),
            dir.path().join("checkpoints.jsonl"),
            dir.path().join("buffer"),
            tpm,
            ext,
            signer,
            cfg,
        )
        .unwrap();
        ServerContext::new(svc, None)
    }

    #[test]
    fn append_get_verify_over_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(&dir);
        let resp = ctx.handle_request(&json!({
            "method": "Append",
            "params": {"payload": {"question": "что в базе?"}, "kind": "RECORD_KIND_PROMPT",
                        "source": "rag-core", "subject": "d8"},
            "id": 1
        }));
        assert_eq!(resp["result"]["seq"], 1);
        assert_eq!(resp["result"]["kind"], "PROMPT");
        let resp = ctx.handle_request(&json!({"method": "GetRecord", "params": {"seq": 1}, "id": 2}));
        assert_eq!(resp["result"]["source"], "rag-core");
        let resp = ctx.handle_request(&json!({
            "method": "VerifyChain", "params": {"deep": true, "verify_signatures": true}, "id": 3
        }));
        assert_eq!(resp["result"]["valid"], true);
    }

    #[test]
    fn append_b64_payload_and_explicit_nonce_replay() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(&dir);
        let payload = b64(b"secret prompt");
        let req = json!({
            "method": "Append",
            "params": {"payload_b64": payload, "kind": "RECORD_KIND_PROMPT",
                        "nonce_b64": b64(&[7u8; 16])},
            "id": 1
        });
        let r1 = ctx.handle_request(&req);
        assert_eq!(r1["result"]["seq"], 1);
        // повтор того же nonce → anti-replay (F-G-03)
        let r2 = ctx.handle_request(&req);
        assert!(r2["error"].as_str().unwrap().contains("nonce"), "{r2}");
    }

    #[test]
    fn publish_checkpoint_and_anchor_status() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(&dir);
        for i in 0..5 {
            ctx.handle_request(&json!({
                "method": "Append",
                "params": {"payload": {"i": i}, "kind": "RECORD_KIND_IPC"}, "id": i
            }));
        }
        let resp = ctx.handle_request(&json!({
            "method": "PublishCheckpoint", "params": {"force": true}, "id": 10
        }));
        assert_eq!(resp["result"]["published"], true);
        assert_eq!(resp["result"]["ext_anchored"], true);
        let cp = &resp["result"]["checkpoint"];
        assert_eq!(cp["last_seq"], 5);
        let status = ctx.handle_request(&json!({"method": "GetAnchorStatus", "id": 11}));
        assert_eq!(status["result"]["seq_ext"], 5);
        assert_eq!(status["result"]["seq_tpm"], 5);
        let recon = ctx.handle_request(&json!({"method": "Reconcile", "id": 12}));
        assert_eq!(recon["result"]["verdict"], "OK");
    }

    #[test]
    fn healthcheck_and_stats() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(&dir);
        let h = ctx.handle_request(&json!({"method": "Healthcheck", "id": 1}));
        assert_eq!(h["result"]["healthy"], true);
        let s = ctx.handle_request(&json!({"method": "GetStats", "id": 2}));
        assert_eq!(s["result"]["sync_policy"], "on_checkpoint");
    }

    #[test]
    fn uds_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("audit.sock");
        let ctx = test_ctx(&dir);
        let s2 = sock.clone();
        std::thread::spawn(move || serve(ctx, s2).unwrap());
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let resp = call_once(&sock, "Append",
            json!({"payload": {"x": 1}, "kind": "RECORD_KIND_IPC"}),
            Duration::from_secs(2)).unwrap();
        assert_eq!(resp["seq"], 1);
        let h = call_once(&sock, "Healthcheck", json!({}), Duration::from_secs(2)).unwrap();
        assert_eq!(h["healthy"], true);
    }
}
