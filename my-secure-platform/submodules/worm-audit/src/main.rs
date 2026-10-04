//! zt-worm-audit — точка входа L7.
//!
//! Команды:
//!   serve        — UDS-сервер контракта audit.proto (+ reconcile при старте)
//!   healthcheck  — одноразовый Healthcheck-запрос
//!   verify       — автономная верификация цепочки
//!   benchmark    — проверка пропускной способности (NF-03)
//!   ingest-spool — поглотить JSONL-спул (bootstrap/gateway) в цепочку
//!   version
//!
//! TPM: в dev/CI используется файловый MockTpm (--tpm-dir); на целевом
//! железе подключается продакшен-реализация TpmOps (tss2/PKCS#11 HSM).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde_json::json;
use zt_worm_audit::anchors::DirectoryAnchor;
use zt_worm_audit::chain::{ChainConfig, ChainWriter, SeedSigner, SyncPolicy};
use zt_worm_audit::checkpoint::CheckpointPolicy;
use zt_worm_audit::record::RecordKind;
use zt_worm_audit::server::{call_once, serve, ServerContext};
use zt_worm_audit::service::{AuditService, ServiceConfig};
use zt_hal_common::tpm::MockTpm;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let result = match cmd {
        "serve" => cmd_serve(&args[1..]),
        "healthcheck" => cmd_healthcheck(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "benchmark" => cmd_benchmark(&args[1..]),
        "ingest-spool" => cmd_ingest_spool(&args[1..]),
        "version" | "--version" => {
            println!(
                "zt-worm-audit {} (ZT-AI-CORE spec v{})",
                env!("CARGO_PKG_VERSION"),
                zt_worm_audit::SPEC_VERSION
            );
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
            eprintln!("zt-worm-audit: ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    eprintln!(
        "zt-worm-audit {ver} — WORM-аудит ZT-AI-CORE (L7)\n\
         \n\
         Использование:\n  \
           zt-worm-audit serve --socket <p> --chain <p> --checkpoints <p> --anchor-dir <p> \
              [--tpm-dir <p>] [--signing-key <p>] [--buffer-dir <p>] \
              [--checkpoint-every-records N] [--checkpoint-every-secs S] \
              [--sync-policy every_record|group_commit|on_checkpoint] [--nonce-ttl-secs N]\n  \
           zt-worm-audit healthcheck --socket <p>\n  \
           zt-worm-audit verify --chain <p> [--signing-key <p>] [--no-signatures]\n  \
           zt-worm-audit benchmark --chain-dir <p> [--records N] [--sync-policy P]\n  \
           zt-worm-audit ingest-spool --chain <p> --spool <p> [--signing-key <p>] [--remove]\n  \
           zt-worm-audit version\n",
        ver = env!("CARGO_PKG_VERSION")
    );
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn require(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing required flag {name}"))
}

fn load_signer(args: &[String], default_name: &str) -> Result<SeedSigner, String> {
    let key_path = PathBuf::from(
        flag(args, "--signing-key")
            .unwrap_or_else(|| format!("/etc/zt-core/keys/{default_name}.seed")),
    );
    if key_path.exists() {
        SeedSigner::load_or_create(&key_path).map_err(|e| e.to_string())
    } else {
        // dev-fallback: детерминированный seed из имени файла (не секрет)
        eprintln!(
            "zt-worm-audit: WARN: signing key {key_path:?} не найден — dev-seed \
             (в prod ключ генерируется в TPM/HSM, scripts/gen-keys.sh)"
        );
        let mut seed = [0u8; 32];
        let name = key_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| default_name.to_string());
        let bytes = name.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            seed[i % 32] ^= b;
            seed[(i + 7) % 32] = seed[(i + 7) % 32].wrapping_add(*b);
        }
        Ok(SeedSigner::from_seed(seed))
    }
}

fn build_config(args: &[String]) -> Result<ServiceConfig, String> {
    let sync = flag(args, "--sync-policy")
        .and_then(|s| SyncPolicy::parse(&s))
        .or_else(|| std::env::var("ZT_WORM_SYNC_POLICY").ok().and_then(|s| SyncPolicy::parse(&s)))
        .unwrap_or_default();
    let nonce_ttl = flag(args, "--nonce-ttl-secs")
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| std::env::var("ZT_WORM_NONCE_TTL_SECS").ok().and_then(|v| v.parse().ok()))
        .unwrap_or(300);
    let every_records = flag(args, "--checkpoint-every-records")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1000);
    let every_secs = flag(args, "--checkpoint-every-secs")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    Ok(ServiceConfig {
        chain: ChainConfig {
            sync_policy: sync,
            nonce_ttl: Duration::from_secs(nonce_ttl),
            clock_skew_tolerance: Duration::from_secs(nonce_ttl),
        },
        checkpoint_policy: CheckpointPolicy {
            every_records,
            every_interval: Duration::from_secs(every_secs),
        },
        tpm_nv_index: flag(args, "--tpm-nv-index")
            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0x0150_0001),
        tpm_min_interval: Duration::from_secs(
            flag(args, "--tpm-min-interval-secs")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600), // F-G-05: ≤ 1 записи/час
        ),
    })
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let socket = PathBuf::from(require(args, "--socket")?);
    let chain_path = PathBuf::from(require(args, "--chain")?);
    let checkpoints = PathBuf::from(require(args, "--checkpoints")?);
    let anchor_dir = PathBuf::from(require(args, "--anchor-dir")?);
    let tpm_dir = PathBuf::from(flag(args, "--tpm-dir").unwrap_or_else(|| {
        std::env::var("ZT_TPM_MOCK_DIR")
            .unwrap_or_else(|_| "/var/lib/zt-core/tpm-mock".to_string())
    }));
    let buffer_dir = PathBuf::from(
        flag(args, "--buffer-dir").unwrap_or_else(|| anchor_dir.join("buffered").to_string_lossy().to_string()),
    );
    let config = build_config(args)?;
    let signer = load_signer(args, "worm-signing")?;

    let tpm = MockTpm::open(&tpm_dir).map_err(|e| format!("mock tpm open: {e}"))?;
    let ext = DirectoryAnchor::new(&anchor_dir).map_err(|e| e.to_string())?;
    let mut service = AuditService::open(
        &chain_path, &checkpoints, &buffer_dir, tpm, ext, Box::new(signer), config,
    )
    .map_err(|e| e.to_string())?;

    // F-G-04: сверка с якорями при КАЖДОМ старте (anti-truncation, AC-03).
    let report = service.reconcile_at_startup().map_err(|e| e.to_string())?;
    println!(
        "reconcile: verdict={:?} seq_local={} seq_tpm={} seq_ext={} write_locked={}",
        report.verdict, report.seq_local, report.anchors.seq_tpm,
        report.anchors.seq_ext, report.write_locked
    );
    if report.wear_alert {
        eprintln!("zt-worm-audit: ALERT: износ TPM NV ≥ 80% → DEGRADED (F-G-05)");
    }
    let report_json = serde_json::to_value(&report).ok();
    let ctx = ServerContext::new(service, report_json);
    serve(ctx, &socket).map_err(|e| e.to_string())
}

fn cmd_healthcheck(args: &[String]) -> Result<(), String> {
    let socket = PathBuf::from(require(args, "--socket")?);
    match call_once(&socket, "Healthcheck", json!({}), Duration::from_secs(3)) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let chain = PathBuf::from(require(args, "--chain")?);
    let signatures = flag(args, "--no-signatures").is_none();
    let signer = load_signer(args, "worm-signing")?;
    let report = zt_worm_audit::chain::verify_chain(
        &chain,
        true,
        signatures,
        if signatures { Some(&signer as &dyn zt_worm_audit::chain::ChainSigner) } else { None },
        0,
        0,
    );
    println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    if !report.valid {
        eprintln!("verify: ЦЕПОЧКА НЕВАЛИДНА (инцидент, runbook §2)");
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_benchmark(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(require(args, "--chain-dir")?);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let records = flag(args, "--records").and_then(|v| v.parse::<u64>().ok()).unwrap_or(10_000);
    let sync = flag(args, "--sync-policy")
        .and_then(|s| SyncPolicy::parse(&s))
        .unwrap_or(SyncPolicy::GroupCommit { max_records: 5000, max_interval_ms: 10_000 });
    let signer = load_signer(args, "worm-signing")?;
    let path = dir.join(format!("bench-{}.jsonl", std::process::id()));
    let mut w = ChainWriter::open(
        &path,
        ChainConfig { sync_policy: sync, ..Default::default() },
        Box::new(signer),
    )
    .map_err(|e| e.to_string())?;
    let started = Instant::now();
    for i in 0..records {
        w.append(
            format!("benchmark-payload-{i}").as_bytes(),
            RecordKind::Ipc,
            "benchmark",
            "d8",
            None,
            None,
        )
        .map_err(|e| e.to_string())?;
    }
    w.sync_now().map_err(|e| e.to_string())?;
    let elapsed = started.elapsed();
    let rate = records as f64 / elapsed.as_secs_f64();
    println!(
        "benchmark: {records} записей за {elapsed:?} = {rate:.0} записей/с (sync={})",
        sync.as_str()
    );
    let _ = std::fs::remove_file(&path);
    if cfg!(not(debug_assertions)) && rate < 10_000.0 {
        eprintln!("NF-03: пропускная способность ниже 10 000 записей/с");
        std::process::exit(3);
    }
    Ok(())
}

fn cmd_ingest_spool(args: &[String]) -> Result<(), String> {
    let chain_path = PathBuf::from(require(args, "--chain")?);
    let spool = PathBuf::from(require(args, "--spool")?);
    let remove = flag(args, "--remove").is_some();
    let signer = load_signer(args, "worm-signing")?;
    let tpm_dir = PathBuf::from(flag(args, "--tpm-dir").unwrap_or_else(|| "/tmp/zt-tpm-ingest".into()));
    let tpm = MockTpm::open(&tpm_dir).map_err(|e| e.to_string())?;
    let ext = DirectoryAnchor::new(chain_path.parent().unwrap_or(&chain_path).join("anchors"))
        .map_err(|e| e.to_string())?;
    let mut service = AuditService::open(
        &chain_path,
        chain_path.with_extension("checkpoints.jsonl"),
        chain_path.parent().unwrap_or(&chain_path).join("buffer"),
        tpm,
        ext,
        Box::new(signer),
        ServiceConfig::default(),
    )
    .map_err(|e| e.to_string())?;
    let n = service.ingest_spool(&spool, remove).map_err(|e| e.to_string())?;
    println!("ingest-spool: {n} записей включено в цепочку");
    Ok(())
}
