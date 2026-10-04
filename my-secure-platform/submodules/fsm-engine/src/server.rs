//! UDS-сервер контракта `fsm.proto` (line-oriented JSON, транспорт dev-контура;
//! в prod — grpc over UDS с теми же сообщениями).
//!
//! Методы: GetState, RequestTransition, RunSelfTest, StageUpdate,
//! CommitUpdate, Rollback, GetRollbackStatus, DumpState, GetWalTail, Healthcheck.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::audit::AuditClient;
use crate::engine::{EngineConfig, FsmEngine};
use crate::state::{LifecycleState, OperatingMode, TransitionTrigger};
use crate::wal::{tail as wal_tail, SelfTestItemPayload, SelfTestPayload};

/// Общий контекст сервера.
pub struct ServerContext {
    pub engine: Mutex<FsmEngine>,
    pub audit: Mutex<Option<AuditClient>>,
    pub running: AtomicBool,
    pub started_at: Instant,
}

impl ServerContext {
    pub fn new(
        wal_path: impl AsRef<Path>,
        config: EngineConfig,
        audit_socket: Option<PathBuf>,
    ) -> Result<Arc<Self>, String> {
        let engine = FsmEngine::open(
            wal_path,
            config,
            Box::new(crate::engine::ImmediateWatchdog),
        )
        .map_err(|e| format!("engine open failed: {e}"))?;
        let audit = audit_socket.map(|p| AuditClient::new(p, Duration::from_secs(2)));
        Ok(Arc::new(Self {
            engine: Mutex::new(engine),
            audit: Mutex::new(audit),
            running: AtomicBool::new(true),
            started_at: Instant::now(),
        }))
    }

    fn engine(&self) -> Result<MutexGuard<'_, FsmEngine>, String> {
        self.engine.lock().map_err(|e| format!("engine lock poisoned: {e}"))
    }

    /// Опубликовать событие в WORM (best-effort, см. audit.rs).
    fn publish_event(&self, event: &crate::engine::StateEvent) {
        if let Ok(mut guard) = self.audit.lock() {
            if let Some(client) = guard.as_mut() {
                if let Err(e) = client.append_fsm_event(event) {
                    eprintln!("[zt-fsm-engine] WARN: audit publish failed: {e}");
                }
            }
        }
    }

    /// Обработка одного JSON-запроса.
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
            "GetState" => {
                let e = self.engine()?;
                Ok(serde_json::to_value(e.snapshot()).map_err(|x| x.to_string())?)
            }
            "RequestTransition" => {
                let to_lifecycle = parse_state(params.get("target_lifecycle"))?;
                let to_mode = parse_mode(params.get("target_mode"))?;
                let trigger = parse_trigger(params.get("trigger"));
                let reason = params.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                let mut e = self.engine()?;
                match e.request_transition(to_lifecycle, to_mode, trigger, reason) {
                    Ok(event) => {
                        drop(e);
                        self.publish_event(&event);
                        Ok(json!({
                            "accepted": true,
                            "state": serde_json::to_value(&event.current).unwrap_or_default(),
                            "duration_ms": event.duration_ms,
                        }))
                    }
                    Err(err) => {
                        // ВАЖНО: guard `e` ещё жив — snapshot берём через него,
                        // повторный self.engine() на том же потоке был бы дедлоком.
                        let snapshot = e.snapshot();
                        let matrix_violation =
                            matches!(err, crate::engine::EngineError::MatrixViolation { .. });
                        Ok(json!({
                            "accepted": false,
                            "rejection_reason": err.to_string(),
                            "matrix_violation": matrix_violation,
                            "state": serde_json::to_value(snapshot).unwrap_or_default(),
                        }))
                    }
                }
            }
            "RunSelfTest" => {
                let full = params.get("full").and_then(|v| v.as_bool()).unwrap_or(true);
                self.run_self_test(full)
            }
            "StageUpdate" => {
                let slot = match params.get("target_slot").and_then(|v| v.as_str()) {
                    Some("B") | Some("SLOT_B") => crate::rollback::UpdateSlot::B,
                    _ => return Err("target_slot must be B (F-I-03)".into()),
                };
                let version = params
                    .get("version_number")
                    .and_then(|v| v.as_u64())
                    .ok_or("version_number required")?;
                let artifact_b64 = params
                    .get("artifact_b64")
                    .and_then(|v| v.as_str())
                    .ok_or("artifact_b64 required")?;
                let sig_b64 = params
                    .get("signature_b64")
                    .and_then(|v| v.as_str())
                    .ok_or("signature_b64 required")?;
                let pk_b64 = params
                    .get("signer_public_key_b64")
                    .and_then(|v| v.as_str())
                    .ok_or("signer_public_key_b64 required")?;
                let artifact = crate::audit::base64_lite::decode(artifact_b64)
                    .map_err(|e| format!("artifact_b64: {e}"))?;
                let sig_vec = crate::audit::base64_lite::decode(sig_b64)
                    .map_err(|e| format!("signature_b64: {e}"))?;
                let pk_vec = crate::audit::base64_lite::decode(pk_b64)
                    .map_err(|e| format!("signer_public_key_b64: {e}"))?;
                if sig_vec.len() != 64 || pk_vec.len() != 32 {
                    return Err("signature must be 64 bytes, key 32 bytes".into());
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&sig_vec);
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&pk_vec);
                let artifact_hash = blake3::hash(&artifact).to_hex().to_string();
                let mut e = self.engine()?;
                let status = e
                    .stage_update(slot, version, &artifact_hash, &artifact, &sig, &pk)
                    .map_err(|x| x.to_string())?;
                Ok(serde_json::to_value(status).map_err(|x| x.to_string())?)
            }
            "CommitUpdate" => {
                let mut e = self.engine()?;
                let status = e.commit_update().map_err(|x| x.to_string())?;
                Ok(json!({"committed": true, "rollback": status}))
            }
            "Rollback" => {
                let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                let mut e = self.engine()?;
                let status = e.rollback_update(reason).map_err(|x| x.to_string())?;
                Ok(json!({"rolled_back": true, "rollback": status}))
            }
            "GetRollbackStatus" => {
                let e = self.engine()?;
                Ok(serde_json::to_value(e.rollback_status()).map_err(|x| x.to_string())?)
            }
            "DumpState" => {
                let e = self.engine()?;
                let dump = e.dump_state();
                let text = serde_json::to_string(&dump).map_err(|x| x.to_string())?;
                Ok(json!({
                    "json_dump": text,
                    "dump_blake3": blake3::hash(text.as_bytes()).to_hex().to_string(),
                    "timestamp_unix_ns": crate::wal::now_ns(),
                }))
            }
            "GetWalTail" => {
                let max = params.get("max_records").and_then(|v| v.as_u64()).unwrap_or(16) as usize;
                let wal_path = {
                    let e = self.engine()?;
                    e.wal_path().to_path_buf()
                };
                let records = wal_tail(&wal_path, max).map_err(|x| x.to_string())?;
                let incomplete = {
                    let e = self.engine()?;
                    e.recovery_info().dangling_intent.is_some()
                };
                Ok(json!({
                    "records": records,
                    "incomplete_intent_found": incomplete,
                }))
            }
            "Healthcheck" => {
                let e = self.engine()?;
                let snap = e.snapshot();
                Ok(json!({
                    "healthy": true,
                    "lifecycle": snap.lifecycle,
                    "mode": snap.mode,
                    "epoch": snap.epoch,
                    "write_locked": snap.write_locked,
                    "uptime_secs": self.started_at.elapsed().as_secs_f64(),
                }))
            }
            other => Err(format!("unknown method: {other}")),
        }
    }

    /// RunSelfTest: детерминированные проверки ядра FSM + платформы.
    pub fn run_self_test(&self, full: bool) -> Result<Value, String> {
        let started = Instant::now();
        let mut items: Vec<SelfTestItemPayload> = Vec::new();

        // 1. Матрица Приложения А (самопроверка инварианта кода).
        let t = Instant::now();
        let matrix_ok = crate::state::matrix_allowed(LifecycleState::Boot, OperatingMode::Nominal)
            && !crate::state::matrix_allowed(LifecycleState::Boot, OperatingMode::Isolated)
            && crate::state::matrix_allowed(LifecycleState::BootFailsafe, OperatingMode::Recovery)
            && crate::state::matrix_allowed(LifecycleState::Running, OperatingMode::Recovery)
            && !crate::state::matrix_allowed(LifecycleState::SelfTest, OperatingMode::Recovery);
        items.push(SelfTestItemPayload {
            name: "matrix_appendix_a".into(),
            passed: matrix_ok,
            detail: if matrix_ok { "инвариант матрицы соблюдён" } else { "матрица повреждена" }.into(),
            duration_ms: t.elapsed().as_millis() as u64,
        });

        // 2. WAL консистентен (recover без mid-file corruption).
        let t = Instant::now();
        let wal_path = {
            let e = self.engine()?;
            e.wal_path().to_path_buf()
        };
        let wal_ok = match crate::wal::recover(&wal_path) {
            Ok(rec) => !rec.mid_file_corruption,
            Err(_) => false,
        };
        items.push(SelfTestItemPayload {
            name: "wal_integrity".into(),
            passed: wal_ok,
            detail: wal_path.display().to_string(),
            duration_ms: t.elapsed().as_millis() as u64,
        });

        // 3. Платформа: glibc (F-E-08).
        let t = Instant::now();
        let glibc = zt_hal_common::platform::runtime_is_glibc();
        items.push(SelfTestItemPayload {
            name: "platform_glibc".into(),
            passed: glibc,
            detail: if glibc { "glibc runtime (F-E-08)" } else { "НЕ glibc — musl запрещён" }.into(),
            duration_ms: t.elapsed().as_millis() as u64,
        });

        // 4. Rollback-инвариант (F-F-03).
        let t = Instant::now();
        let inv = {
            let e = self.engine()?;
            let s = e.rollback_status();
            !(s.pending_rollback_counter > 0 && s.rollback_allowed)
        };
        items.push(SelfTestItemPayload {
            name: "rollback_invariant".into(),
            passed: inv,
            detail: "rollback запрещён при незавершённом SELF_TEST".into(),
            duration_ms: t.elapsed().as_millis() as u64,
        });

        if full {
            // 5. Крипто-профиль (Приложение Б): контрольный BLAKE3-вектор.
            let t = Instant::now();
            let crypto_ok = zt_hal_common::crypto::blake3_hex(b"")
                == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
            items.push(SelfTestItemPayload {
                name: "crypto_blake3_vector".into(),
                passed: crypto_ok,
                detail: "контрольный вектор BLAKE3".into(),
                duration_ms: t.elapsed().as_millis() as u64,
            });

            // 6. KSM должен быть выключен (F-E-05) — warning, не fail,
            //    если sysfs недоступен (контейнер).
            let t = Instant::now();
            let ksm = zt_hal_common::platform::ksm_is_disabled(Path::new("/sys"));
            items.push(SelfTestItemPayload {
                name: "ksm_disabled".into(),
                passed: ksm.unwrap_or(true),
                detail: match ksm {
                    Some(true) => "KSM off".into(),
                    Some(false) => "KSM ВКЛЮЧЁН — требуется echo 0 > /sys/kernel/mm/ksm/run".into(),
                    None => "sysfs недоступен (контейнер) — проверка пропущена".into(),
                },
                duration_ms: t.elapsed().as_millis() as u64,
            });
        }

        let passed = items.iter().all(|i| i.passed);
        let total_ms = started.elapsed().as_millis() as u64;
        let report = SelfTestPayload { passed, total_duration_ms: total_ms, items };

        // Вердикт → rollback-менеджеру + WAL; автопереход при SELF_TEST-лайфсайкле.
        let auto_transition = {
            let e = self.engine()?;
            e.lifecycle() == LifecycleState::SelfTest
        };
        if passed {
            let mut e = self.engine()?;
            e.record_self_test_passed(&report).map_err(|x| x.to_string())?;
        } else {
            let mut e = self.engine()?;
            let _ = e.notify_self_test_failed("self-test items failed");
        }
        let mut event_json = Value::Null;
        if auto_transition && passed {
            let mut e = self.engine()?;
            match e.request_transition(
                LifecycleState::Running,
                OperatingMode::Nominal,
                TransitionTrigger::SelfTestPass,
                "SELF_TEST passed",
            ) {
                Ok(ev) => {
                    drop(e);
                    self.publish_event(&ev);
                    event_json = serde_json::to_value(&ev).unwrap_or_default();
                }
                Err(err) => event_json = json!({"error": err.to_string()}),
            }
        }

        Ok(json!({
            "passed": report.passed,
            "items": report.items,
            "total_duration_ms": report.total_duration_ms,
            "timestamp_unix_ns": crate::wal::now_ns(),
            "transition": event_json,
        }))
    }
}

fn parse_state(v: Option<&Value>) -> Result<LifecycleState, String> {
    let s = v.and_then(|x| x.as_str()).ok_or("target_lifecycle required")?;
    LifecycleState::parse(s).ok_or_else(|| format!("unknown lifecycle: {s}"))
}

fn parse_mode(v: Option<&Value>) -> Result<OperatingMode, String> {
    let s = v.and_then(|x| x.as_str()).ok_or("target_mode required")?;
    OperatingMode::parse(s).ok_or_else(|| format!("unknown mode: {s}"))
}

fn parse_trigger(v: Option<&Value>) -> TransitionTrigger {
    match v.and_then(|x| x.as_str()).unwrap_or("") {
        "TRIGGER_OPERATOR" => TransitionTrigger::Operator,
        "TRIGGER_BOOT_OK" => TransitionTrigger::BootOk,
        "TRIGGER_SELF_TEST_PASS" => TransitionTrigger::SelfTestPass,
        "TRIGGER_SELF_TEST_FAIL" => TransitionTrigger::SelfTestFail,
        "TRIGGER_WORM_TRUNCATION" => TransitionTrigger::WormTruncation,
        "TRIGGER_SHUTDOWN_REQUESTED" => TransitionTrigger::ShutdownRequested,
        _ => TransitionTrigger::Unspecified,
    }
}

/// Запустить сервер на Unix-сокете (блокирующий accept-loop).
pub fn serve(ctx: Arc<ServerContext>, socket_path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = socket_path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    // Права на сокет: только владелец (операционный пользователь zt-core).
    set_socket_permissions(&path);
    eprintln!(
        "[zt-fsm-engine] serving on {} (wal={})",
        path.display(),
        ctx.engine()
            .map(|e| e.wal_path().display().to_string())
            .unwrap_or_else(|_| "?".into())
    );
    for stream in listener.incoming() {
        if !ctx.running.load(Ordering::Relaxed) {
            break;
        }
        match stream {
            Ok(stream) => {
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || handle_connection(ctx, stream));
            }
            Err(e) => eprintln!("[zt-fsm-engine] accept error: {e}"),
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn set_socket_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn handle_connection(ctx: Arc<ServerContext>, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    // F-E-04: проверка SO_PEERCRED клиента.
    if let Err(e) = verify_peer(&stream) {
        eprintln!("[zt-fsm-engine] peer rejected: {e}");
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

/// SO_PEERCRED: клиент — root или пользователь zt-core (uid из env).
fn verify_peer(stream: &UnixStream) -> Result<(i32, u32, u32), String> {
    // SO_PEERCRED через getsockopt(2): struct ucred { pid_t; uid_t; gid_t; }
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
            "getsockopt(SO_PEERCRED) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let allowed_uids: Vec<u32> = std::env::var("ZT_IPC_ALLOWED_UIDS")
        .unwrap_or_else(|_| "0".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if !allowed_uids.contains(&cred.uid) {
        return Err(format!("uid {} not in allow-list {allowed_uids:?}", cred.uid));
    }
    Ok((cred.pid, cred.uid, cred.gid))
}

/// Одноразовый клиентский вызов (для healthcheck-бинаря и тестов).
pub fn call_once(
    socket_path: impl AsRef<Path>,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<Value, String> {
    let stream = UnixStream::connect(socket_path.as_ref())
        .map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let req = json!({
        "jsonrpc": "zt-uds/1.0",
        "method": method,
        "params": params,
        "id": crate::wal::now_ns(),
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

/// Тип записи WAL для внешнего аудита (re-export для main).
pub use crate::wal::WalRecordType;

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(dir: &tempfile::TempDir) -> Arc<ServerContext> {
        ServerContext::new(dir.path().join("wal.log"), EngineConfig::default(), None).unwrap()
    }

    #[test]
    fn get_state_and_transition_over_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(&dir);
        let resp = c.handle_request(&json!({"method": "GetState", "id": 1}));
        assert_eq!(resp["result"]["lifecycle"], "BOOT");
        let resp = c.handle_request(&json!({
            "method": "RequestTransition",
            "params": {"target_lifecycle": "SELF_TEST", "target_mode": "NOMINAL",
                        "trigger": "TRIGGER_BOOT_OK", "reason": "boot"},
            "id": 2
        }));
        assert_eq!(resp["result"]["accepted"], true);
        let resp = c.handle_request(&json!({"method": "GetState", "id": 3}));
        assert_eq!(resp["result"]["lifecycle"], "SELF_TEST");
    }

    #[test]
    fn invalid_transition_reported_not_thrown() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(&dir);
        let resp = c.handle_request(&json!({
            "method": "RequestTransition",
            "params": {"target_lifecycle": "BOOT", "target_mode": "ISOLATED"},
            "id": 1
        }));
        assert_eq!(resp["result"]["accepted"], false);
        assert_eq!(resp["result"]["matrix_violation"], true);
    }

    #[test]
    fn run_self_test_passes_and_moves_to_running() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(&dir);
        c.handle_request(&json!({
            "method": "RequestTransition",
            "params": {"target_lifecycle": "SELF_TEST", "target_mode": "NOMINAL",
                        "trigger": "TRIGGER_BOOT_OK"},
            "id": 1
        }));
        let resp = c.handle_request(&json!({"method": "RunSelfTest", "params": {"full": true}, "id": 2}));
        assert_eq!(resp["result"]["passed"], true, "{resp}");
        let state = c.handle_request(&json!({"method": "GetState", "id": 3}));
        assert_eq!(state["result"]["lifecycle"], "RUNNING");
    }

    #[test]
    fn healthcheck_and_dump_state() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(&dir);
        let h = c.handle_request(&json!({"method": "Healthcheck", "id": 1}));
        assert_eq!(h["result"]["healthy"], true);
        let d = c.handle_request(&json!({"method": "DumpState", "id": 2}));
        assert!(d["result"]["dump_blake3"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn unknown_method_error() {
        let dir = tempfile::tempdir().unwrap();
        let c = ctx(&dir);
        let resp = c.handle_request(&json!({"method": "Fly", "id": 1}));
        assert!(resp["error"].as_str().unwrap().contains("unknown method"));
    }

    #[test]
    fn uds_roundtrip_call_once() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("fsm.sock");
        let c = ServerContext::new(dir.path().join("wal.log"), EngineConfig::default(), None).unwrap();
        let serve_sock = sock.clone();
        std::thread::spawn(move || serve(c, serve_sock).unwrap());
        // ждём появления сокета
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let state = call_once(&sock, "GetState", json!({}), Duration::from_secs(2)).unwrap();
        assert_eq!(state["lifecycle"], "BOOT");
        let tr = call_once(
            &sock,
            "RequestTransition",
            json!({"target_lifecycle": "SHUTDOWN", "target_mode": "NOMINAL",
                   "trigger": "TRIGGER_SHUTDOWN_REQUESTED", "reason": "test"}),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(tr["accepted"], true);
    }
}
