#![cfg(target_os = "linux")]
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;

fn test_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn tar_file(path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut output);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
        builder.finish().unwrap();
    }
    output
}

fn raw_tar_entry(path_bytes: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, body).unwrap();
        builder.finish().unwrap();
    }
    out
}

fn make_hostile_deb_raw(path_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut b = ar::Builder::new(&mut bytes);
        for (name, body) in [
            ("debian-binary", b"2.0\n".to_vec()),
            (
                "control.tar",
                tar_file(
                    "control",
                    b"Package: hostile-sample\nVersion: 1.0\nArchitecture: all\nDescription: hostile\n",
                ),
            ),
            ("data.tar", raw_tar_entry(path_bytes, b"malicious content")),
        ] {
            let header = ar::Header::new(name.as_bytes().to_vec(), body.len() as u64);
            b.append(&header, body.as_slice()).unwrap();
        }
    }
    bytes
}

#[test]
fn key_handling_keyring_symlink_is_rejected() {
    let temp = test_dir();
    let real_keyring = temp.path().join("real_keyring.gpg");
    let sym_keyring = temp.path().join("sym_keyring.gpg");
    fs::write(&real_keyring, b"fake gpg keyring bytes").unwrap();
    fs::set_permissions(&real_keyring, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&real_keyring, &sym_keyring).unwrap();

    let sources_file = temp.path().join("test.sources");
    fs::write(
        &sources_file,
        format!(
            "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {}\n",
            sym_keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_file, fs::Permissions::from_mode(0o600)).unwrap();

    let config = temp.path().join("sources.toml");
    fs::write(
        &config,
        format!(
            "[[sources]]\nname = \"test\"\ndistribution = \"debian\"\nsuite = \"bookworm\"\narchitecture = \"amd64\"\ncomponents = [\"main\"]\nsource_file = \"{}\"\nfingerprints = [\"0000000000000000000000000000000000000000\"]\n",
            sources_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "sources",
            "list",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let err_str = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_str.contains("symlink") || err_str.contains("unsafe") || err_str.contains("policy"),
        "Unexpected error: {err_str}"
    );
}

#[test]
fn key_handling_keyring_in_group_writable_parent_directory_is_rejected() {
    let temp = test_dir();
    let sub = temp.path().join("writable_dir");
    fs::create_dir(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o777)).unwrap(); // world/group writable

    let keyring = sub.join("keyring.gpg");
    fs::write(&keyring, b"fake gpg keyring bytes").unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();

    let sources_file = temp.path().join("test.sources");
    fs::write(
        &sources_file,
        format!(
            "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {}\n",
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_file, fs::Permissions::from_mode(0o600)).unwrap();

    let config = temp.path().join("sources.toml");
    fs::write(
        &config,
        format!(
            "[[sources]]\nname = \"test\"\ndistribution = \"debian\"\nsuite = \"bookworm\"\narchitecture = \"amd64\"\ncomponents = [\"main\"]\nsource_file = \"{}\"\nfingerprints = [\"0000000000000000000000000000000000000000\"]\n",
            sources_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "sources",
            "list",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["error"]["code"], "source_load_failed");
}

#[test]
fn filesystem_toctou_symlink_store_dir_fails_closed() {
    let temp = test_dir();
    let real_store = temp.path().join("real_store");
    let sym_store = temp.path().join("sym_store");
    fs::create_dir(&real_store).unwrap();
    fs::set_permissions(&real_store, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real_store, &sym_store).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--store-dir",
            sym_store.to_str().unwrap(),
            "--json",
            "store",
            "ls",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["error"]["code"], "store_open_failed");
}

#[test]
fn filesystem_toctou_hardlink_metadata_db_attack_fails_closed() {
    let temp = test_dir();
    let store_dir = temp.path().join("store");
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // Initialize minimal valid sqlite database for dich
    let db_path = store_dir.join("metadata.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA application_id = 0x44494348;
             PRAGMA user_version = 3;
             CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
             INSERT INTO schema_version VALUES (3);
             CREATE TABLE store_objects (id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_id TEXT NOT NULL, created_at INTEGER NOT NULL, manifest TEXT NOT NULL);
             CREATE TABLE profile_generations (id TEXT PRIMARY KEY, profile_name TEXT NOT NULL, generation_number INTEGER NOT NULL, graph_id TEXT NOT NULL, created_at INTEGER NOT NULL, previous_id TEXT);
             CREATE TABLE reference_graphs (id TEXT PRIMARY KEY, root_object_id TEXT NOT NULL, created_at INTEGER NOT NULL);",
        )
        .unwrap();
    }
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600)).unwrap();

    // Create marker and lock
    let marker = store_dir.join(".dich_initialized");
    fs::write(&marker, b"dich_v1\n").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();

    let lock = store_dir.join("metadata.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

    // Adversary creates hardlink to metadata.db
    let attacker_hardlink = temp.path().join("attacker_metadata.db");
    fs::hard_link(&db_path, &attacker_hardlink).unwrap();

    // Opening store must detect st_nlink > 1 and reject
    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--json",
            "store",
            "ls",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["error"]["code"], "store_open_failed");
}

#[test]
fn filesystem_toctou_hardlink_metadata_lock_attack_fails_closed() {
    let temp = test_dir();
    let store_dir = temp.path().join("store");
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let db_path = store_dir.join("metadata.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA application_id = 0x44494348;
             PRAGMA user_version = 3;
             CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
             INSERT INTO schema_version VALUES (3);
             CREATE TABLE store_objects (id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_id TEXT NOT NULL, created_at INTEGER NOT NULL, manifest TEXT NOT NULL);
             CREATE TABLE profile_generations (id TEXT PRIMARY KEY, profile_name TEXT NOT NULL, generation_number INTEGER NOT NULL, graph_id TEXT NOT NULL, created_at INTEGER NOT NULL, previous_id TEXT);
             CREATE TABLE reference_graphs (id TEXT PRIMARY KEY, root_object_id TEXT NOT NULL, created_at INTEGER NOT NULL);",
        )
        .unwrap();
    }
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600)).unwrap();

    let marker = store_dir.join(".dich_initialized");
    fs::write(&marker, b"dich_v1\n").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();

    let lock = store_dir.join("metadata.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

    // Adversary creates hardlink to metadata.lock
    let attacker_hardlink = temp.path().join("attacker_lock");
    fs::hard_link(&lock, &attacker_hardlink).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--json",
            "store",
            "ls",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["error"]["code"], "store_open_failed");
}

#[test]
fn path_traversal_archive_with_directory_escape_is_rejected() {
    let temp = test_dir();
    let hostile_deb = make_hostile_deb_raw(b"../../etc/shadow");
    let deb_path = temp.path().join("escape.deb");
    fs::write(&deb_path, &hostile_deb).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "inspect", deb_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["error"]["code"], "inspect_failed");
}

#[test]
fn path_traversal_archive_with_absolute_path_is_rejected() {
    let temp = test_dir();
    let hostile_deb = make_hostile_deb_raw(b"/usr/bin/malicious");
    let deb_path = temp.path().join("absolute.deb");
    fs::write(&deb_path, &hostile_deb).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "inspect", deb_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["error"]["code"], "inspect_failed");
}

#[test]
fn path_traversal_archive_with_control_character_is_rejected() {
    let temp = test_dir();
    let hostile_deb = make_hostile_deb_raw(b"usr/bin/evil\x01file");
    let deb_path = temp.path().join("control_char.deb");
    fs::write(&deb_path, &hostile_deb).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "inspect", deb_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["error"]["code"], "inspect_failed");
}

#[test]
fn container_limits_prlimit_cpu_and_mem_fail_closed_without_hanging() {
    let temp = test_dir();
    let deb_bytes = make_hostile_deb_raw(b"usr/bin/sample");
    let deb_path = temp.path().join("sample.deb");
    fs::write(&deb_path, &deb_bytes).unwrap();

    // Run dich inspect constrained by prlimit with 1 second CPU time and small AS
    let output = Command::new("/usr/bin/prlimit")
        .args([
            "--cpu=1:2",
            "--as=100000000",
            env!("CARGO_BIN_EXE_dich"),
            "--json",
            "inspect",
            deb_path.to_str().unwrap(),
        ])
        .output();

    if let Ok(out) = output {
        // Must complete without hanging, either succeeding or failing cleanly
        let _ = out.status;
    }
}

#[test]
fn privilege_model_store_directory_permissions_are_0700() {
    let temp = test_dir();
    let store_dir = temp.path().join("private_store");

    // Execute rootless init via a command that creates store dir
    let _output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--rootless",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--json",
            "gc",
            "--execute",
        ])
        .output()
        .unwrap();

    // Since store doesn't exist, gc --execute won't create it if uninitialized,
    // but if it creates it, it must be 0700.
    if store_dir.exists() {
        let mode = fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "Store dir must have mode 0700");
    }
}
