#![cfg(target_os = "linux")]
use std::process::Command;
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn fetch_requires_identity_and_uses_default_freshness_policy() {
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
        "--config",
        "/no/such/config",
    ]);
    assert!(!out.status.success());
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["code"], "source_load_failed");
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

#[test]
#[ignore = "requires explicit original signed Release, xz index and artifact fixtures"]
fn real_signed_cached_artifact_fetch() {
    use dich_apt::{
        FreshnessPolicy, IndexFormat, IndexLimits, SnapshotJournal, authorize_artifact,
        load_configured_sources, select_indexed_artifact, validate_release,
        verify_configured_inrelease,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::Path,
        time::{Duration, SystemTime},
    };
    let env = |name| std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"));
    let config = env("DICH_REAL_CONFIG");
    let cache = env("DICH_REAL_CACHE");
    let package = env("DICH_REAL_PACKAGE");
    let version = env("DICH_REAL_VERSION");
    let component = env("DICH_REAL_COMPONENT");
    let age = env("DICH_REAL_MAX_AGE");
    let allow = std::env::var("DICH_REAL_ALLOW_MISSING_VALID_UNTIL")
        .ok()
        .as_deref()
        == Some("1");
    let sources = load_configured_sources(Path::new(&config)).unwrap();
    assert_eq!(sources.len(), 1);
    let policy = FreshnessPolicy::new(
        Duration::from_secs(age.parse().unwrap()),
        Duration::from_secs(300),
        !allow,
    )
    .unwrap();
    let input = fs::read(env("DICH_REAL_RELEASE")).unwrap();
    let verified = verify_configured_inrelease(&sources[0], &input).unwrap();
    let release = validate_release(&verified, SystemTime::now(), policy).unwrap();
    let journal = SnapshotJournal::open(Path::new(&cache)).unwrap();
    journal.store_release(&release).unwrap();
    let compressed = fs::read(env("DICH_REAL_INDEX")).unwrap();
    journal
        .store_index(
            &release,
            &component,
            IndexFormat::Xz,
            &compressed,
            IndexLimits::default(),
        )
        .unwrap();
    let (release, index) = journal
        .load_index(
            &sources[0],
            policy,
            &component,
            IndexFormat::Xz,
            IndexLimits::default(),
        )
        .unwrap();
    let artifact = select_indexed_artifact(&index, &package, &version).unwrap();
    authorize_artifact(&release, &artifact, SystemTime::now()).unwrap();
    let bytes = fs::read(env("DICH_REAL_ARTIFACT")).unwrap();
    assert_eq!(bytes.len() as u64, artifact.size());
    assert_eq!(Sha256::digest(&bytes).as_slice(), artifact.sha256());
    let hex = artifact
        .sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let blob = Path::new(&cache).join(format!("blob-{hex}"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&blob)
        .unwrap();
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
    use std::io::Write;
    file.write_all(&bytes).unwrap();
    drop(file);
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
    if allow {
        command.arg("--allow-missing-valid-until");
    }
    let out = command
        .args([
            "fetch",
            &package,
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
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["state"], "cached");
    assert_eq!(result["artifact_sha256"], hex);
    assert_eq!(result["installable"], false);
}
