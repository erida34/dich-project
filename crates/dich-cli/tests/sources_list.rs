#![cfg(target_os = "linux")]
use std::{fs, process::Command};

#[test]
fn signed_cached_archive_can_publish_a_tree_without_running_scripts() {
    use dich_apt::{
        FreshnessPolicy, IndexFormat, IndexLimits, SnapshotJournal, load_configured_sources,
        validate_release, verify_configured_inrelease,
    };
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt,
        process::Stdio,
        time::{Duration, SystemTime},
    };
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let home = dir.path().join("gnupg");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let gpg = |args: &[&str]| {
        Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(
        gpg(&[
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Dich publish fixture <test@example.invalid>",
            "ed25519",
            "sign",
            "0"
        ])
        .status
        .success()
    );
    let listing = gpg(&["--batch", "--with-colons", "--list-keys"]);
    let fingerprint = String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .unwrap()
        .split(':')
        .nth(9)
        .unwrap()
        .to_owned();
    let keyring = dir.path().join("keyring.gpg");
    let exported = gpg(&["--batch", "--export", &fingerprint]);
    assert!(exported.status.success());
    fs::write(&keyring, exported.stdout).unwrap();
    let source_file = dir.path().join("fixture.sources");
    let config = dir.path().join("sources.toml");
    let cache_dir = dir.path().join("cache");
    let store_dir = dir.path().join("store");
    fs::create_dir(&cache_dir).unwrap();
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&source_file, format!("Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {}\n", keyring.display())).unwrap();
    fs::write(&config, format!("[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"{}\"]\n", source_file.display(), keyring.display(), fingerprint)).unwrap();
    let marker = dir.path().join("script-executed");
    let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
    let make_tar = |entries: &[(&str, &[u8])]| {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            for &(path, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, content).unwrap();
            }
            builder.finish().unwrap();
        }
        bytes
    };
    let control = make_tar(&[
        (
            "control",
            b"Package: fixturetree\nVersion: 1.0-1\nArchitecture: amd64\n",
        ),
        ("postinst", script.as_bytes()),
    ]);
    let data = make_tar(&[("usr/share/fixturetree/data", b"fixture content")]);
    let mut archive = Vec::new();
    {
        let mut builder = ar::Builder::new(&mut archive);
        for (name, body) in [
            ("debian-binary", b"2.0\n".to_vec()),
            ("control.tar", control),
            ("data.tar", data),
        ] {
            let header = ar::Header::new(name.as_bytes().to_vec(), body.len() as u64);
            builder.append(&header, body.as_slice()).unwrap();
        }
    }
    let hex = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let artifact_hash = hex(&archive);
    let package_index = format!(
        "Package: fixturetree\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/f/fixturetree/fixturetree_1.0-1_amd64.deb\nSize: {}\nSHA256: {}\n\n",
        archive.len(),
        artifact_hash
    );
    let mut gzip = Command::new("gzip")
        .args(["-n", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    gzip.stdin
        .take()
        .unwrap()
        .write_all(package_index.as_bytes())
        .unwrap();
    let compressed = gzip.wait_with_output().unwrap();
    assert!(compressed.status.success());
    let date = Command::new("date")
        .args(["-u", "+%a, %d %b %Y %H:%M:%S UTC"])
        .output()
        .unwrap();
    let release = format!(
        "Origin: Debian\nSuite: bookworm\nDate: {}SHA256:\n {} {} main/binary-amd64/Packages.gz\n",
        String::from_utf8(date.stdout).unwrap(),
        hex(&compressed.stdout),
        compressed.stdout.len()
    );
    let release_path = dir.path().join("Release-publish");
    let signed_path = dir.path().join("InRelease-publish");
    fs::write(&release_path, release).unwrap();
    let signed = gpg(&[
        "--batch",
        "--yes",
        "--clearsign",
        "--output",
        signed_path.to_str().unwrap(),
        release_path.to_str().unwrap(),
    ]);
    assert!(signed.status.success());
    let source = load_configured_sources(&config).unwrap().remove(0);
    let verified = verify_configured_inrelease(&source, &fs::read(&signed_path).unwrap()).unwrap();
    let freshness =
        FreshnessPolicy::new(Duration::from_secs(86400), Duration::from_secs(300), false).unwrap();
    let release = validate_release(&verified, SystemTime::now(), freshness).unwrap();
    let journal = SnapshotJournal::open(&cache_dir).unwrap();
    journal.store_release(&release).unwrap();
    journal
        .store_index(
            &release,
            "main",
            IndexFormat::Gzip,
            &compressed.stdout,
            IndexLimits::default(),
        )
        .unwrap();
    let blob = cache_dir.join(format!("blob-{artifact_hash}"));
    fs::write(&blob, archive).unwrap();
    fs::set_permissions(blob, fs::Permissions::from_mode(0o600)).unwrap();
    let fetch = || {
        Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--store-dir",
                store_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "fetch",
                "fixturetree",
                "--exact-version",
                "1.0-1",
                "--component",
                "main",
                "--publish-tree",
            ])
            .output()
            .unwrap()
    };
    let result = fetch();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["state"], "cached");
    assert_eq!(body["tree"]["publication"], "published");
    assert_eq!(body["tree"]["lifecycle"], "extracted");
    assert_eq!(body["tree"]["compatibility"], "not_analyzed");
    assert_eq!(body["installable"], false);
    let id = body["tree"]["id"].as_str().unwrap();
    assert_eq!(
        fs::read(
            store_dir
                .join("objects")
                .join(format!("{id}.tree/usr/share/fixturetree/data"))
        )
        .unwrap(),
        b"fixture content"
    );
    assert!(!marker.exists());
    let verify = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "store",
            "verify",
            id,
            "--kind",
            "tree",
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let reused = fetch();
    assert!(reused.status.success());
    let body: serde_json::Value = serde_json::from_slice(&reused.stdout).unwrap();
    assert_eq!(body["tree"]["publication"], "reused");
    assert!(!marker.exists());
}

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
    for (name, version, max_bytes) in [("fixture", "1.0-1", "1"), ("fixture", "99", "1024")] {
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
                "fetch",
                name,
                "--exact-version",
                version,
                "--component",
                "main",
                "--max-bytes",
                max_bytes,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], "fetch_failed");
    }
    let blob =
        cache_dir.join("blob-0c190c47a57eaf9b339049983978ff0bec52a1d19576c679c40a366cba1d4bc6");
    let fixture = include_bytes!("../../dich-apt/tests/fixtures/index/fixture.deb");
    fs::write(&blob, fixture).unwrap();
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
    let cached_fetch = || {
        Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "fetch",
                "fixture",
                "--exact-version",
                "1.0-1",
                "--component",
                "main",
                "--max-bytes",
                "1024",
            ])
            .output()
            .unwrap()
    };
    let cached = cached_fetch();
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(body["state"], "cached");
    assert_eq!(body["installable"], false);
    assert_eq!(
        body["artifact_sha256"],
        "0c190c47a57eaf9b339049983978ff0bec52a1d19576c679c40a366cba1d4bc6"
    );
    // The signed index fixture is intentionally not an extractable .deb.
    let invalid_store = dir.path().join("invalid-store");
    fs::create_dir(&invalid_store).unwrap();
    fs::set_permissions(&invalid_store, fs::Permissions::from_mode(0o700)).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--store-dir",
            invalid_store.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "fetch",
            "fixture",
            "--exact-version",
            "1.0-1",
            "--component",
            "main",
            "--publish-tree",
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!invalid_store.join("objects").exists());
    let lock_path = fs::read_dir(&cache_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().ends_with(".lock"))
        .unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let busy = cached_fetch();
    assert!(!busy.status.success());
    assert!(busy.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&busy.stderr).unwrap();
    assert_eq!(error["error"]["code"], "fetch_failed");
    drop(lock);
    fs::write(&blob, b"corrupt").unwrap();
    let bad_cached = cached_fetch();
    assert!(!bad_cached.status.success());
    assert!(bad_cached.stdout.is_empty());
    fs::write(&blob, fixture).unwrap();
    let index_path = fs::read_dir(&cache_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("index-")
        })
        .unwrap();
    let saved = fs::read(&index_path).unwrap();
    for tamper in ["index", "keyring"] {
        if tamper == "index" {
            fs::write(&index_path, b"corrupt").unwrap();
        } else {
            fs::write(&index_path, &saved).unwrap();
            fs::write(&keyring, b"forged keyring").unwrap();
        }
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
                "fetch",
                "fixture",
                "--exact-version",
                "1.0-1",
                "--component",
                "main",
                "--max-bytes",
                "1024",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{tamper}");
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], "fetch_failed");
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
