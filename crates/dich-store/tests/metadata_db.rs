#![cfg(target_os = "linux")]
use dich_store::MetadataDb;
use std::os::unix::fs::{PermissionsExt, symlink};

fn private_dir() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}
#[test]
fn metadata_uses_wal_full_durability_and_reopens() {
    let root = private_dir();
    let db = MetadataDb::open(root.path()).unwrap();
    assert_eq!(db.journal_mode().unwrap(), "wal");
    assert_eq!(db.synchronous().unwrap(), 2);
    assert_eq!(db.schema_version().unwrap(), 2);
    drop(db);
    assert_eq!(
        MetadataDb::open(root.path())
            .unwrap()
            .schema_version()
            .unwrap(),
        2
    );
}
#[test]
fn rejects_untrusted_directory_or_symlinked_database() {
    let root = private_dir();
    let target = root.path().join("other");
    std::fs::write(&target, b"sentinel").unwrap();
    symlink(&target, root.path().join("metadata.sqlite3")).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
}

#[test]
fn refuses_unknown_or_forged_schema_without_rewriting_it() {
    let root = private_dir();
    let path = root.path().join("metadata.sqlite3");
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE unrelated (x INTEGER); PRAGMA application_id = 1145652040; PRAGMA user_version = 1;").unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn refuses_symlinked_wal_sidecar() {
    let root = private_dir();
    let target = root.path().join("target");
    std::fs::write(&target, b"sentinel").unwrap();
    symlink(&target, root.path().join("metadata.sqlite3-wal")).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
}

#[test]
fn database_and_wal_files_are_private_and_hardlinks_are_rejected() {
    let root = private_dir();
    let db = MetadataDb::open(root.path()).unwrap();
    for name in [
        "metadata.sqlite3",
        "metadata.sqlite3-wal",
        "metadata.sqlite3-shm",
    ] {
        let path = root.path().join(name);
        if path.exists() {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }
    drop(db);
    let outside = root.path().join("hardlink");
    std::fs::hard_link(root.path().join("metadata.sqlite3"), &outside).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
}

#[test]
fn rejects_symlinked_store_directory() {
    let root = private_dir();
    let target = root.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = root.path().join("alias");
    symlink(&target, &alias).unwrap();
    assert!(MetadataDb::open(&alias).is_err());
    assert!(!target.join("metadata.sqlite3").exists());
}

#[test]
fn preexisting_empty_database_is_not_silently_adopted() {
    let root = private_dir();
    let path = root.path().join("metadata.sqlite3");
    std::fs::write(&path, []).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn exclusive_lock_blocks_another_process_until_database_closes() {
    let root = private_dir();
    let db = MetadataDb::open(root.path()).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "child_observes_busy_store"])
        .env("DICH_STORE_TEST_DIR", root.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    drop(db);
    assert!(MetadataDb::open(root.path()).is_ok());
}

#[test]
#[ignore = "subprocess helper"]
fn child_observes_busy_store() {
    let path = std::env::var_os("DICH_STORE_TEST_DIR").unwrap();
    assert!(matches!(
        MetadataDb::open(std::path::Path::new(&path)),
        Err(dich_store::MetadataError::Busy)
    ));
}

#[test]
fn lock_symlink_or_hardlink_cannot_redirect_store_operations() {
    let root = private_dir();
    let target = root.path().join("protected");
    std::fs::write(&target, b"sentinel").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let lock = root.path().join("metadata.lock");
    symlink(&target, &lock).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::hard_link(&target, &lock).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
}

#[test]
fn upgrades_known_v1_metadata_schema_transactionally() {
    let root = private_dir();
    let path = root.path().join("metadata.sqlite3");
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE publication_intents (object_id TEXT PRIMARY KEY NOT NULL, stage_name TEXT NOT NULL, created_at INTEGER NOT NULL); PRAGMA application_id = 1145652040; PRAGMA user_version = 1;").unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let db = MetadataDb::open(root.path()).unwrap();
    assert_eq!(db.schema_version().unwrap(), 2);
}
