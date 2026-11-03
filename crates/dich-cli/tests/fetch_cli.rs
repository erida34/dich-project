#![cfg(target_os = "linux")]
use std::process::Command;
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn fetch_requires_explicit_identity_and_freshness_and_fails_closed() {
    for args in [
        &["--json", "fetch", "sample"][..],
        &["--json", "fetch", "sample", "--exact-version", "1"][..],
    ] {
        let out = run(args);
        assert!(!out.status.success());
        let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(error["error"]["code"], "invalid_arguments");
    }
    let out = run(&[
        "--json",
        "fetch",
        "sample",
        "--exact-version",
        "1",
        "--component",
        "main",
    ]);
    assert!(!out.status.success());
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["code"], "freshness_policy_required");
    assert!(out.stdout.is_empty());
    let out = run(&[
        "--json",
        "--config",
        "/no/such/config",
        "--max-age-seconds",
        "3600",
        "fetch",
        "sample",
        "--exact-version",
        "1",
        "--component",
        "main",
    ]);
    assert!(!out.status.success());
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["code"], "source_load_failed");
    assert!(out.stdout.is_empty());
}

#[test]
#[ignore = "requires an explicitly configured source, fresh dedicated cache and network"]
fn live_exact_fetch_downloads_signed_artifact() {
    let config = std::env::var("DICH_LIVE_CONFIG").expect("DICH_LIVE_CONFIG");
    let cache = std::env::var("DICH_LIVE_CACHE").expect("DICH_LIVE_CACHE");
    let age = std::env::var("DICH_LIVE_MAX_AGE").expect("DICH_LIVE_MAX_AGE");
    let name = std::env::var("DICH_LIVE_PACKAGE").expect("DICH_LIVE_PACKAGE");
    let version = std::env::var("DICH_LIVE_VERSION").expect("DICH_LIVE_VERSION");
    let component = std::env::var("DICH_LIVE_COMPONENT").expect("DICH_LIVE_COMPONENT");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dich"));
    command.args([
        "--json",
        "--config",
        &config,
        "--cache",
        &cache,
        "--max-age-seconds",
        &age,
    ]);
    if std::env::var("DICH_LIVE_ALLOW_MISSING_VALID_UNTIL")
        .ok()
        .as_deref()
        == Some("1")
    {
        command.arg("--allow-missing-valid-until");
    }
    let out = command
        .args([
            "fetch",
            &name,
            "--exact-version",
            &version,
            "--component",
            &component,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        body["state"], "downloaded",
        "use a dedicated cache without this artifact"
    );
    assert_eq!(body["name"], name);
    assert_eq!(body["version"], version);
    assert_eq!(body["installable"], false);
    assert_eq!(body["artifact_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(body["release_sha256"].as_str().unwrap().len(), 64);
    assert!(body["size"].as_u64().unwrap() > 0);
}
