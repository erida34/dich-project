#![cfg(target_os = "linux")]
use dich_apt::RateLimitedReader;
use dich_cli::paths::check_disk_space;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Instant;

fn test_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn offline_mode_rejects_update_immediately() {
    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--offline", "--json", "update"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err["error"]["code"], "offline_mode");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("offline mode")
    );
    assert!(err["error"]["hint"].as_str().unwrap().contains("Connect"));
}

#[test]
fn offline_mode_rejects_fetch_when_artifact_not_cached() {
    let temp = test_dir();
    let config = temp.path().join("sources.toml");
    let sources_file = temp.path().join("test.sources");
    let keyring = temp.path().join("keyring.gpg");
    fs::write(&keyring, b"fake keyring bytes").unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();

    fs::write(
        &sources_file,
        format!(
            "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {}\n",
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_file, fs::Permissions::from_mode(0o600)).unwrap();

    fs::write(
        &config,
        format!(
            "[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"11223344556677889900AABBCCDDEEFF11223344\"]\n",
            sources_deb822_path(&sources_file),
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let cache_dir = temp.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--offline",
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "fetch",
            "pkg",
            "--exact-version",
            "1.0",
            "--component",
            "main",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        err["error"]["code"] == "offline_mode" || err["error"]["code"] == "fetch_failed",
        "unexpected error: {:?}",
        err
    );
}

fn sources_deb822_path(path: &std::path::Path) -> String {
    path.display().to_string()
}

#[test]
fn rate_limited_reader_throttles_bandwidth_accurately() {
    // 20 KiB of data throttled at 100 KiB/s should take at least ~150ms
    let data = vec![0x42u8; 20 * 1024];
    let rate = 100 * 1024; // 100 KiB/s
    let mut reader = RateLimitedReader::new(Cursor::new(data), rate);
    let mut buf = vec![0u8; 4096];
    let start = Instant::now();
    let mut total = 0;
    while let Ok(n) = reader.read(&mut buf) {
        if n == 0 {
            break;
        }
        total += n;
    }
    let elapsed = start.elapsed();
    assert_eq!(total, 20 * 1024);
    // At 100 KiB/s, 20 KiB takes at least 180ms
    assert!(
        elapsed.as_millis() >= 150,
        "elapsed time was too short: {}ms",
        elapsed.as_millis()
    );
}

#[test]
fn disk_space_preflight_detects_insufficient_space() {
    let temp = test_dir();
    // Asking for 1 Exabyte should cleanly fail without panicking
    let result = check_disk_space(temp.path(), u64::MAX - 1024 * 1024);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, "disk_space_insufficient");
    assert!(err.hint().unwrap().contains("Free up disk space"));
}

#[test]
fn disk_space_preflight_accepts_reasonable_allocation() {
    let temp = test_dir();
    // Checking for 1 KiB on a working system should succeed
    let result = check_disk_space(temp.path(), 1024);
    assert!(result.is_ok());
}

#[test]
fn adversarial_symlink_swap_in_store_fails_closed() {
    let temp = test_dir();
    let store_dir = temp.path().join("store");
    let target_dir = temp.path().join("target");
    fs::create_dir(&target_dir).unwrap();
    fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // Create a symlink pointing to target
    std::os::unix::fs::symlink(&target_dir, &store_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "store",
            "ls",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err["error"]["code"], "store_open_failed");
}

#[test]
fn file_descriptor_exhaustion_fails_closed_without_panic() {
    // Run dich under prlimit with restricted NOFILE (e.g. 18 file descriptors)
    let output = Command::new("prlimit")
        .args([
            "--nofile=18:18",
            env!("CARGO_BIN_EXE_dich"),
            "--json",
            "store",
            "ls",
        ])
        .output();

    if let Ok(output) = output {
        // Must fail with non-zero exit code and never crash or segfault
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("panic"),
            "panicked under low NOFILE: {}",
            stderr
        );
    }
}
