#![cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(args)
        .output()
        .unwrap()
}
fn store() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn archive_fixture(root: &std::path::Path) -> String {
    drop(dich_store::MetadataDb::open(root).unwrap());
    let bytes = b"verified fixture";
    let hash = Sha256::digest(bytes);
    let mut identity = b"dich.store.identity\0v1\0".to_vec();
    fn field(out: &mut Vec<u8>, v: &[u8]) {
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    }
    for v in [
        "sample",
        "1",
        "amd64",
        "debian",
        "bookworm",
        "https://example.org/debian",
        "amd64",
    ] {
        field(&mut identity, v.as_bytes());
    }
    for v in ["main", "012345"] {
        identity.extend_from_slice(&1u32.to_be_bytes());
        field(&mut identity, v.as_bytes());
    }
    field(&mut identity, b"pool/main/s/sample.deb");
    identity.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    identity.extend_from_slice(&hash);
    identity.extend_from_slice(&[2; 32]);
    identity.extend_from_slice(&2u32.to_be_bytes());
    let id = Sha256::digest(&identity)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let objects = root.join("objects");
    fs::create_dir(&objects).unwrap();
    fs::set_permissions(&objects, fs::Permissions::from_mode(0o700)).unwrap();
    let path = objects.join(format!("{id}.deb"));
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let db = rusqlite::Connection::open(root.join("metadata.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO verified_archives VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, identity, bytes.len() as i64, hash.as_slice()],
    )
    .unwrap();
    id
}
#[test]
fn store_commands_fail_closed_without_creating_store() {
    let root = store();
    let p = root.path().to_str().unwrap();
    let out = run(&["--json", "--store-dir", p, "store", "ls"]);
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["status"], "error");
    assert!(!root.path().join("metadata.sqlite3").exists());
    assert!(!root.path().join("metadata.lock").exists());
}
#[test]
fn store_list_and_verify_distinguish_metadata_from_local_integrity() {
    let root = store();
    let id = archive_fixture(root.path());
    let p = root.path().to_str().unwrap();
    let out = run(&["--json", "--store-dir", p, "store", "ls"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["objects"][0]["id"], id);
    assert_eq!(body["scope"], "metadata_only");
    assert_eq!(body["objects"][0]["recorded_lifecycle"], "downloaded");
    assert_eq!(body["objects"][0]["content_verified"], false);
    assert_eq!(body["objects"][0]["compatibility"], "not_analyzed");
    assert_eq!(body["objects"][0]["installable"], false);
    let out = run(&[
        "--json",
        "--store-dir",
        p,
        "store",
        "verify",
        &id,
        "--kind",
        "archive",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["scope"], "local_metadata_only");
    assert_eq!(body["recorded_lifecycle"], "downloaded");
    assert_eq!(body["content_verified"], true);
    assert_eq!(body["compatibility"], "not_analyzed");
    assert_eq!(body["installable"], false);
    let file = root.path().join("objects").join(format!("{id}.deb"));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, b"tampered fixture").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    let out = run(&[
        "--json",
        "--store-dir",
        p,
        "store",
        "verify",
        &id,
        "--kind",
        "archive",
    ]);
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["error"]["code"], "store_verify_failed");
}

#[test]
fn store_cli_fails_closed_on_lock_contention_and_unsafe_paths() {
    let root = store();
    let db = dich_store::MetadataDb::open(root.path()).unwrap();
    let p = root.path().to_str().unwrap();
    let out = run(&["--json", "--store-dir", p, "store", "ls"]);
    assert!(!out.status.success());
    let body: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(body["error"]["code"], "store_open_failed");
    drop(db);
    let link = root.path().join("linked");
    std::os::unix::fs::symlink(root.path(), &link).unwrap();
    let out = run(&[
        "--json",
        "--store-dir",
        link.to_str().unwrap(),
        "store",
        "ls",
    ]);
    assert!(!out.status.success());
    let out = run(&[
        "--json",
        "--store-dir",
        p,
        "store",
        "verify",
        "../bad",
        "--kind",
        "archive",
    ]);
    assert!(!out.status.success());
    let body: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(body["error"]["code"], "store_verify_failed");
}
