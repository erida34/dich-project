#![cfg(target_os = "linux")]
use std::{fs, process::Command};

#[test]
fn lists_configured_sources_and_reports_json_errors() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let source = dir.path().join("example.sources");
    let config = dir.path().join("sources.toml");
    fs::write(&source, "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/example.gpg\n").unwrap();
    let policy = format!(
        "[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"/usr/share/keyrings/example.gpg\"\nfingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n",
        source.display()
    );
    fs::write(&config, policy).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "sources",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["sources"][0]["suite"], "bookworm");
    let missing = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "--config", "/no/such/config", "sources", "list"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let error: serde_json::Value = serde_json::from_slice(&missing.stderr).unwrap();
    assert_eq!(error["schema_version"], 1);
    assert_eq!(error["error"]["code"], "source_load_failed");
    let human = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--config", config.to_str().unwrap(), "sources", "list"])
        .output()
        .unwrap();
    assert!(human.status.success());
    assert!(
        String::from_utf8_lossy(&human.stdout)
            .contains("configured\thttps://example.org/debian\tbookworm\tamd64\tmain")
    );
    for args in [["--json", "install"], ["--json", "unknown"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["schema_version"], 1);
    }
    let update = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            dir.path().to_str().unwrap(),
            "update",
        ])
        .output()
        .unwrap();
    assert!(!update.status.success());
    let error: serde_json::Value = serde_json::from_slice(&update.stderr).unwrap();
    assert_eq!(error["error"]["code"], "freshness_policy_required");
    let query = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            dir.path().to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "search",
            "fixture",
        ])
        .output()
        .unwrap();
    assert!(!query.status.success());
    assert!(query.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&query.stderr).unwrap();
    assert_eq!(error["error"]["code"], "query_failed");
}

#[test]
fn cached_query_cli_outputs_authenticated_fixture_offline() {
    use dich_apt::{
        FreshnessPolicy, IndexFormat, IndexLimits, SnapshotJournal, load_configured_sources,
        validate_release, verify_configured_inrelease,
    };
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let home = dir.path().join("gnupg");
    fs::create_dir(&home).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let gpg = |args: &[&str]| {
        Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(args)
            .output()
            .unwrap()
    };
    let generated = gpg(&[
        "--batch",
        "--passphrase",
        "",
        "--quick-generate-key",
        "Dich test fixture <test@example.invalid>",
        "ed25519",
        "sign",
        "0",
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let listing = gpg(&["--batch", "--with-colons", "--list-keys"]);
    assert!(listing.status.success());
    let fingerprint = String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .unwrap()
        .split(':')
        .nth(9)
        .unwrap()
        .to_string();
    let keyring = dir.path().join("keyring.gpg");
    let exported = gpg(&["--batch", "--export", &fingerprint]);
    assert!(exported.status.success());
    fs::write(&keyring, exported.stdout).unwrap();
    let source_file = dir.path().join("fixture.sources");
    let config = dir.path().join("sources.toml");
    let cache_dir = dir.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    fs::write(&source_file, format!("Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {}\n", keyring.display())).unwrap();
    fs::write(&config, format!("[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"{}\"]\n", source_file.display(), keyring.display(), fingerprint)).unwrap();
    let date = Command::new("date")
        .args(["-u", "+%a, %d %b %Y %H:%M:%S UTC"])
        .output()
        .unwrap();
    assert!(date.status.success());
    let date = String::from_utf8(date.stdout).unwrap();
    let release = format!(
        "Origin: Debian\nSuite: bookworm\nDate: {}SHA256:\n fa184974c07c71db02266b3a06849f8804e9e3930963a90102136ccabf99d0a5 224 main/binary-amd64/Packages.xz\n",
        date
    );
    let release_path = dir.path().join("Release");
    let signed_path = dir.path().join("InRelease");
    fs::write(&release_path, release).unwrap();
    let signed = gpg(&[
        "--batch",
        "--yes",
        "--clearsign",
        "--output",
        signed_path.to_str().unwrap(),
        release_path.to_str().unwrap(),
    ]);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let sources = load_configured_sources(&config).unwrap();
    let verified =
        verify_configured_inrelease(&sources[0], &fs::read(signed_path).unwrap()).unwrap();
    let policy =
        FreshnessPolicy::new(Duration::from_secs(86400), Duration::from_secs(300), false).unwrap();
    let release = validate_release(&verified, SystemTime::now(), policy).unwrap();
    let journal = SnapshotJournal::open(&cache_dir).unwrap();
    journal.store_release(&release).unwrap();
    journal
        .store_index(
            &release,
            "main",
            IndexFormat::Xz,
            include_bytes!("../../dich-apt/tests/fixtures/index/Packages.xz"),
            IndexLimits::default(),
        )
        .unwrap();
    let planned = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "plan",
            "fixture",
            "--distribution",
            "debian",
            "--suite",
            "bookworm",
            "--architecture",
            "amd64",
        ])
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(body["status"], "planned");
    assert_eq!(
        body["pins"][0]["artifact_sha256"],
        "0c190c47a57eaf9b339049983978ff0bec52a1d19576c679c40a366cba1d4bc6"
    );
    assert_eq!(body["pins"][0]["architecture"], "amd64");
    assert_eq!(body["pins"][0]["suite"], "bookworm");
    assert_eq!(
        body["pins"][0]["release_sha256"].as_str().unwrap().len(),
        64
    );
    assert_eq!(body["packages"], serde_json::json!(["fixture=1.0-1"]));
    assert!(
        body["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("fixture=1.0-1"))
    );
    for (name, distribution, expected) in [
        ("missing", "debian", "unsatisfiable"),
        ("fixture", "ubuntu", "plan_input_failed"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "plan",
                name,
                "--distribution",
                distribution,
                "--suite",
                "bookworm",
                "--architecture",
                "amd64",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], expected);
        if expected == "unsatisfiable" {
            assert!(!error["error"]["trace"].as_array().unwrap().is_empty());
        }
    }
    for command in ["search", "show", "versions"] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                command,
                "fixture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"schema_version":1,"status":"completed","records":[{"name":"fixture","version":"1.0-1","architecture":"amd64","source":"https://example.org/debian","suite":"bookworm"}]})
        );
    }
}

#[test]
fn mutation_commands_fail_closed_without_running_input() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let marker = dir.path().join("should-not-exist");
    let payload = format!("$(touch {})", marker.display());
    for args in [
        vec!["install", payload.as_str()],
        vec!["remove", payload.as_str()],
        vec!["rollback"],
        vec!["gc", "--execute"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .arg("--json")
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let body: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(body["error"]["code"], "unsupported");
        assert!(!marker.exists());
    }
}
