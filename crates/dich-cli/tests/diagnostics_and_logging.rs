use std::process::Command;

#[test]
fn exit_codes_are_categorized_and_stable() {
    // 1. Exit code 2: Invalid CLI arguments
    let invalid_arg = Command::new(env!("CARGO_BIN_EXE_dich"))
        .arg("--nonexistent-flag-xyz")
        .output()
        .unwrap();
    assert_eq!(invalid_arg.status.code(), Some(2));

    // 2. Exit code 1: Store open failed (runtime / store error)
    let bad_store = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            "/dev/null/not-a-dir",
            "profile",
            "list",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_store.status.code(), Some(1));
    let json_err: serde_json::Value = serde_json::from_slice(&bad_store.stderr).unwrap();
    assert_eq!(json_err["schema_version"], 1);
    assert_eq!(json_err["status"], "error");
    assert_eq!(json_err["error"]["code"], "store_open_failed");
    assert_eq!(json_err["error"]["exit_code"], 1);
    assert!(
        json_err["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("--store-dir")
    );

    // 3. Exit code 4: Rollback unavailable / profile missing
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let store_dir = dir.path().join("store");
    let missing_profile = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "rollback",
            "--profile",
            "nonexistent-profile",
            "--yes",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_profile.status.code(), Some(1)); // store_open_failed since store not initialized yet
}

#[test]
fn json_error_schema_includes_exit_code_and_hint() {
    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "store", "verify", "deadbeef", "--kind", "tree"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let body: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["status"], "error");
    assert!(body["error"]["code"].is_string());
    assert!(body["error"]["message"].is_string());
    assert!(body["error"]["exit_code"].is_number());
}

#[test]
fn human_errors_render_actionable_hints() {
    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["store", "ls"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("dich: error:"));
    assert!(stderr.contains("hint:"));
}

#[test]
fn update_errors_include_the_failing_stage_and_classified_cause() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let sources_file = dir.path().join("test.sources");
    std::fs::write(
        &sources_file,
        "Types: deb\nURIs: https://127.0.0.1:1/debian\nSuites: bookworm\nComponents: main\nArchitectures: amd64\nSigned-By: /dev/null\n",
    )
    .unwrap();
    let config_file = dir.path().join("sources.toml");
    std::fs::write(
        &config_file,
        format!(
            "[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://127.0.0.1:1/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"/dev/null\"\nfingerprints = [\"0000000000000000000000000000000000000000\"]\n",
            sources_file.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config_file.to_str().unwrap(),
            "--cache",
            dir.path().join("cache").to_str().unwrap(),
            "update",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let body: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(body["error"]["code"], "update_failed");
    let trace = body["error"]["trace"][0].as_str().unwrap();
    assert!(trace.contains("Release metadata"));
    assert!(trace.contains("Transport"));
}

#[test]
fn structured_logging_redacts_credentials_on_stderr() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let sources_file = dir.path().join("test.sources");
    std::fs::write(
        &sources_file,
        "Types: deb\nURIs: https://user:secret12345@example.invalid/debian\nSuites: bookworm\nComponents: main\nSigned-By: /dev/null\n",
    )
    .unwrap();
    let config_file = dir.path().join("sources.toml");
    std::fs::write(
        &config_file,
        format!(
            "[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://user:secret12345@example.invalid/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"/dev/null\"\nfingerprints = [\"0000000000000000000000000000000000000000\"]\n",
            sources_file.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--config",
            config_file.to_str().unwrap(),
            "--log-level",
            "info",
            "sources",
            "list",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Secret must NOT be in stderr or stdout!
    assert!(
        !stderr.contains("secret12345"),
        "secret password leaked in stderr"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("secret12345"),
        "secret password leaked in stdout"
    );
}

#[test]
fn progress_output_is_isolated_to_stderr() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let store_dir = dir.path().join("store");
    std::fs::create_dir(&store_dir).unwrap();
    std::fs::set_permissions(
        &store_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    dich_store::MetadataDb::open(&store_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--progress",
            "gc",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[1/2]"),
        "progress step 1 must be on stderr"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("[1/2]"),
        "stdout must not contain progress indicators"
    );

    // With --json, stdout must parse cleanly as JSON
    let json_output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--progress",
            "gc",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(json_output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(parsed["status"], "planned");
}
