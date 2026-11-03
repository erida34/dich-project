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
    for args in [["--json", "update"], ["--json", "unknown"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["schema_version"], 1);
    }
}
