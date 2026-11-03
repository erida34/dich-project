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
