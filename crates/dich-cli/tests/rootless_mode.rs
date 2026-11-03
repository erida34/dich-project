#![cfg(target_os = "linux")]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn test_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn rootless_conflicts_with_system_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--rootless", "--system", "sources", "list"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("conflicts with"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn read_only_store_command_never_creates_directories() {
    let temp = test_dir();
    let data_home = temp.path().join("data");
    let cache_home = temp.path().join("cache");
    let config_home = temp.path().join("config");

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .env("XDG_DATA_HOME", &data_home)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("XDG_CONFIG_HOME", &config_home)
        .args(["--rootless", "--json", "store", "ls"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err["error"]["code"], "store_open_failed");
    assert!(
        err["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("$XDG_DATA_HOME/dich")
    );

    // Ensure no directories were created on disk by read-only command
    assert!(!data_home.exists());
    assert!(!cache_home.exists());
}

#[test]
fn read_only_profile_list_never_creates_directories() {
    let temp = test_dir();
    let data_home = temp.path().join("data");

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .env("XDG_DATA_HOME", &data_home)
        .args(["--rootless", "--json", "profile", "list"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err["error"]["code"], "store_open_failed");
    assert!(!data_home.exists());
}

#[test]
fn rootless_paths_resolve_from_xdg_and_home_environment() {
    let temp = test_dir();
    let dich_config_dir = temp.path().join("config/dich");
    fs::create_dir_all(&dich_config_dir).unwrap();
    fs::set_permissions(
        temp.path().join("config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&dich_config_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let keyring = dich_config_dir.join("keyring.gpg");
    fs::write(&keyring, b"fake keyring bytes").unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();

    let sources_deb822 = dich_config_dir.join("ubuntu.sources");
    fs::write(
        &sources_deb822,
        format!(
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\nSuites: noble\nComponents: main\nSigned-By: {}\n",
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_deb822, fs::Permissions::from_mode(0o600)).unwrap();

    let sources_file = dich_config_dir.join("sources.toml");
    fs::write(
        &sources_file,
        format!(
            "[[sources]]\ndistribution = \"ubuntu\"\nsources_file = \"{}\"\nuri = \"https://archive.ubuntu.com/ubuntu\"\nsuite = \"noble\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"11223344556677889900AABBCCDDEEFF11223344\"]\n",
            sources_deb822.display(),
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_file, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .args(["--rootless", "sources", "list"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("https://archive.ubuntu.com/ubuntu"));
    assert!(stdout.contains("noble"));
}

#[test]
fn rootless_paths_resolve_from_home_when_xdg_unset() {
    let temp = test_dir();
    let dich_config_dir = temp.path().join(".config/dich");
    fs::create_dir_all(&dich_config_dir).unwrap();
    fs::set_permissions(
        temp.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&dich_config_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let keyring = dich_config_dir.join("keyring.gpg");
    fs::write(&keyring, b"fake keyring bytes").unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();

    let sources_deb822 = dich_config_dir.join("ubuntu.sources");
    fs::write(
        &sources_deb822,
        format!(
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\nSuites: noble\nComponents: main\nSigned-By: {}\n",
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_deb822, fs::Permissions::from_mode(0o600)).unwrap();

    let sources_file = dich_config_dir.join("sources.toml");
    fs::write(
        &sources_file,
        format!(
            "[[sources]]\ndistribution = \"ubuntu\"\nsources_file = \"{}\"\nuri = \"https://archive.ubuntu.com/ubuntu\"\nsuite = \"noble\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"11223344556677889900AABBCCDDEEFF11223344\"]\n",
            sources_deb822.display(),
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_file, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env("HOME", temp.path())
        .args(["--rootless", "sources", "list"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("https://archive.ubuntu.com/ubuntu"));
}

#[test]
fn rootless_mutating_command_ensures_private_directories_with_0700_mode() {
    let temp = test_dir();
    let data_home = temp.path().join("data");
    let cache_home = temp.path().join("cache");

    // Pre-create parent directory with 0700
    fs::create_dir_all(&data_home).unwrap();
    fs::set_permissions(&data_home, fs::Permissions::from_mode(0o700)).unwrap();

    // Call gc --execute in rootless mode: ensure_private_directory creates data_home/dich
    let _output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .env("XDG_DATA_HOME", &data_home)
        .env("XDG_CACHE_HOME", &cache_home)
        .args(["--rootless", "gc", "--execute"])
        .output()
        .unwrap();

    // The store directory should have been created with 0700 permissions
    let store_dir = data_home.join("dich");
    assert!(store_dir.exists(), "store directory was not created");

    let meta = fs::metadata(&store_dir).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o700,
        "store directory permissions should be 0700"
    );
}

#[test]
fn rootless_directory_creation_rejects_unsafe_world_writable_parent() {
    let temp = test_dir();
    let data_home = temp.path().join("unsafe_parent");
    fs::create_dir_all(&data_home).unwrap();
    // Make parent world-writable (unsafe)
    fs::set_permissions(&data_home, fs::Permissions::from_mode(0o777)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .env("XDG_DATA_HOME", &data_home)
        .args(["--rootless", "--json", "gc", "--execute"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err["error"]["code"], "unsafe_permissions");
}

#[test]
fn system_mode_diagnostics_inform_about_privileges_or_rootless() {
    // When an unprivileged user explicitly targets /var/lib/dich which they cannot write to
    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--system", "--json", "store", "ls"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err["error"]["code"], "store_open_failed");
    assert!(
        err["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("/var/lib/dich")
    );
}
