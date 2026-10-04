//! zt-fsm-engine — точка входа L6.
//!
//! Команды:
//!   serve       — UDS-сервер контракта fsm.proto
//!   healthcheck — одноразовый запрос Healthcheck (для docker/CI)
//!   dump        — форензика WAL без запуска движка (runbook §2)
//!   demo        — демонстрационный прогон жизненного цикла
//!   version     — версия

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use zt_fsm_engine::engine::{EngineConfig, ImmediateWatchdog};
use zt_fsm_engine::server::{call_once, serve, ServerContext};
use zt_fsm_engine::state::{LifecycleState as L, OperatingMode as M, TransitionTrigger as T};
use zt_fsm_engine::wal;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let result = match cmd {
        "serve" => cmd_serve(&args[1..]),
        "healthcheck" => cmd_healthcheck(&args[1..]),
        "dump" => cmd_dump(&args[1..]),
        "demo" => cmd_demo(&args[1..]),
        "version" | "--version" => {
            println!("zt-fsm-engine {} (ZT-AI-CORE spec v{})",
                     env!("CARGO_PKG_VERSION"), zt_fsm_engine::SPEC_VERSION);
            Ok(())
        }
        _ => {
            print_help();
            if cmd == "help" || cmd == "--help" { Ok(()) } else { Err("unknown command".into()) }
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zt-fsm-engine: ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    eprintln!(
        "zt-fsm-engine {ver} — FSM-движок ZT-AI-CORE (L6)\n\
         \n\
         Использование:\n  \
           zt-fsm-engine serve --socket <path> --wal <path> [--audit-socket <path>] [--watchdog-timeout-ms N]\n  \
           zt-fsm-engine healthcheck --socket <path>\n  \
           zt-fsm-engine dump --wal <path> [--tail N]\n  \
           zt-fsm-engine demo --wal <path>\n  \
           zt-fsm-engine version\n",
        ver = env!("CARGO_PKG_VERSION")
    );
}

fn get_flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn require_flag(args: &[String], name: &str) -> Result<String, String> {
    get_flag(args, name).ok_or_else(|| format!("missing required flag {name}"))
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let socket = PathBuf::from(require_flag(args, "--socket")?);
    let wal_path = PathBuf::from(require_flag(args, "--wal")?);
    let audit_socket = get_flag(args, "--audit-socket").map(PathBuf::from);
    let watchdog_ms = get_flag(args, "--watchdog-timeout-ms")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(500); // NF-05
    let config = EngineConfig {
        watchdog_timeout: Duration::from_millis(watchdog_ms),
        wal_fsync: get_flag(args, "--no-fsync").is_none(),
    };
    let ctx = ServerContext::new(&wal_path, config, audit_socket)?;
    serve(ctx, &socket).map_err(|e| format!("serve: {e}"))
}

fn cmd_healthcheck(args: &[String]) -> Result<(), String> {
    let socket = PathBuf::from(require_flag(args, "--socket")?);
    match call_once(&socket, "Healthcheck", serde_json::json!({}), Duration::from_secs(3)) {
        Ok(state) => {
            println!("{}", serde_json::to_string_pretty(&state).unwrap_or_default());
            Ok(())
        }
        Err(e) => {
            eprintln!("healthcheck failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_dump(args: &[String]) -> Result<(), String> {
    let wal_path = PathBuf::from(require_flag(args, "--wal")?);
    let tail_n = get_flag(args, "--tail").and_then(|v| v.parse::<usize>().ok()).unwrap_or(16);
    let recovery = wal::recover(&wal_path).map_err(|e| e.to_string())?;
    let records = wal::tail(&wal_path, tail_n).map_err(|e| e.to_string())?;
    let dump = serde_json::json!({
        "wal_path": wal_path.display().to_string(),
        "records_total": recovery.records.len(),
        "last_seq": recovery.last_seq,
        "dangling_intent": recovery.dangling_intent.is_some(),
        "truncated_tail": recovery.truncated_tail,
        "mid_file_corruption": recovery.mid_file_corruption,
        "needs_forced_recovery": recovery.needs_forced_recovery(),
        "tail": records,
    });
    println!("{}", serde_json::to_string_pretty(&dump).map_err(|e| e.to_string())?);
    if recovery.needs_forced_recovery() || recovery.mid_file_corruption {
        eprintln!("dump: WAL требует RECOVERY (см. runbook §2)");
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_demo(args: &[String]) -> Result<(), String> {
    let wal_path = PathBuf::from(require_flag(args, "--wal")?);
    let mut engine = zt_fsm_engine::engine::FsmEngine::open(
        &wal_path,
        EngineConfig::default(),
        Box::new(ImmediateWatchdog),
    )
    .map_err(|e| e.to_string())?;

    println!("== ZT-AI-CORE FSM demo (WAL: {}) ==", wal_path.display());
    println!("start: {}×{} epoch={}", engine.lifecycle(), engine.mode(), engine.epoch());

    let steps = [
        (L::SelfTest, M::Nominal, T::BootOk, "boot integrity ok"),
        (L::Running, M::Nominal, T::SelfTestPass, "self-test passed"),
        (L::Degraded, M::Isolated, T::ExtAnchorDown, "S3 anchor down > 5 min"),
        (L::SelfTest, M::Isolated, T::Operator, "re-test after remediation"),
        (L::Running, M::Nominal, T::SelfTestPass, "recovered"),
    ];
    for (l, m, t, r) in steps {
        let ev = engine.request_transition(l, m, t, r).map_err(|e| e.to_string())?;
        println!(
            "  → {}×{} ({} мс, trigger={:?})",
            ev.current.lifecycle, ev.current.mode, ev.duration_ms, t
        );
    }

    // Попытка запрещённого матрицей перехода — отклоняется детерминированно.
    match engine.request_transition(L::Running, M::Nominal, T::Operator, "") {
        Ok(_) => println!("  (same-state transition accepted as no-op)"),
        Err(e) => println!("  rejected as expected: {e}"),
    }
    println!("final: {}×{} epoch={}", engine.lifecycle(), engine.mode(), engine.epoch());
    Ok(())
}
