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
    assert_eq!(db.schema_version().unwrap(), 4);
    drop(db);
    assert_eq!(
        MetadataDb::open(root.path())
            .unwrap()
            .schema_version()
            .unwrap(),
        4
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
    assert_eq!(db.schema_version().unwrap(), 4);
}

#[test]
fn explicit_empty_initialization_recovery_is_narrow() {
    let root = private_dir();
    let path = root.path().join("metadata.sqlite3");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    MetadataDb::recover_empty_initialization(root.path()).unwrap();
    assert_eq!(
        MetadataDb::open(root.path())
            .unwrap()
            .schema_version()
            .unwrap(),
        4
    );
}
#[test]
fn empty_initialization_recovery_refuses_existing_state_and_sidecars() {
    for name in [
        "objects",
        "staging",
        "metadata.sqlite3-wal",
        "metadata.sqlite3-shm",
        "metadata.sqlite3-journal",
    ] {
        let root = private_dir();
        let path = root.path().join("metadata.sqlite3");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(root.path().join(name), b"sentinel").unwrap();
        assert!(
            MetadataDb::recover_empty_initialization(root.path()).is_err(),
            "{name}"
        );
        assert!(path.exists());
    }
}

#[test]
fn empty_initialization_recovery_refuses_nonempty_or_linked_database() {
    let root = private_dir();
    let db = root.path().join("metadata.sqlite3");
    std::fs::write(&db, b"not empty").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(MetadataDb::recover_empty_initialization(root.path()).is_err());
    assert_eq!(std::fs::read(&db).unwrap(), b"not empty");
    std::fs::remove_file(&db).unwrap();
    let external = tempfile::NamedTempFile::new_in(std::env::var_os("HOME").unwrap()).unwrap();
    std::fs::hard_link(external.path(), &db).unwrap();
    assert!(MetadataDb::recover_empty_initialization(root.path()).is_err());
    assert!(db.exists());
    std::fs::remove_file(&db).unwrap();
    symlink(external.path(), &db).unwrap();
    assert!(MetadataDb::recover_empty_initialization(root.path()).is_err());
    assert!(db.symlink_metadata().unwrap().file_type().is_symlink());
}

#[test]
fn interrupted_initialization_marker_allows_safe_restart() {
    let root = private_dir();
    let marker = root.path().join("metadata.initializing");
    std::fs::write(&marker, b"dich-metadata-init-v1\n").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(root.path().join("metadata.sqlite3"), b"").unwrap();
    std::fs::set_permissions(
        root.path().join("metadata.sqlite3"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        MetadataDb::open(root.path())
            .unwrap()
            .schema_version()
            .unwrap(),
        4
    );
    assert!(!marker.exists());
}
#[test]
fn invalid_initialization_marker_never_authorizes_an_empty_database() {
    let root = private_dir();
    let marker = root.path().join("metadata.initializing");
    std::fs::write(&marker, b"unrecognized").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(root.path().join("metadata.sqlite3"), b"").unwrap();
    std::fs::set_permissions(
        root.path().join("metadata.sqlite3"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    assert!(marker.exists());
}

#[test]
fn missing_database_or_marker_never_hides_existing_store_objects() {
    for with_marker in [false, true] {
        let root = private_dir();
        std::fs::create_dir(root.path().join("objects")).unwrap();
        std::fs::write(root.path().join("objects/sentinel"), b"keep").unwrap();
        if with_marker {
            let marker = root.path().join("metadata.initializing");
            std::fs::write(&marker, b"dich-metadata-init-v1\n").unwrap();
            std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(root.path().join("metadata.sqlite3"), b"").unwrap();
            std::fs::set_permissions(
                root.path().join("metadata.sqlite3"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(MetadataDb::open(root.path()).is_err());
        assert_eq!(
            std::fs::read(root.path().join("objects/sentinel")).unwrap(),
            b"keep"
        );
    }
}

#[test]
fn missing_database_with_sidecar_is_not_recreated() {
    let root = private_dir();
    let wal = root.path().join("metadata.sqlite3-wal");
    std::fs::write(&wal, b"unexamined").unwrap();
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    assert!(!root.path().join("metadata.sqlite3").exists());
    assert_eq!(std::fs::read(wal).unwrap(), b"unexamined");
}

#[test]
fn partial_marker_can_only_be_removed_from_empty_uninitialized_store() {
    let root = private_dir();
    let marker = root.path().join("metadata.initializing");
    std::fs::write(&marker, b"dich-").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
    std::fs::write(root.path().join("other"), b"keep").unwrap();
    assert!(MetadataDb::recover_abandoned_marker(root.path()).is_err());
    std::fs::remove_file(root.path().join("other")).unwrap();
    MetadataDb::recover_abandoned_marker(root.path()).unwrap();
    assert_eq!(
        MetadataDb::open(root.path())
            .unwrap()
            .schema_version()
            .unwrap(),
        4
    );
}

#[test]
fn rejects_special_mode_bits_on_metadata_paths() {
    for name in ["metadata.sqlite3", "metadata.lock", "metadata.initializing"] {
        for bits in [0o1600, 0o2600, 0o4600] {
            let root = private_dir();
            drop(MetadataDb::open(root.path()).unwrap());
            let path = root.path().join(name);
            if name == "metadata.initializing" {
                std::fs::write(&path, b"dich-metadata-init-v1\n").unwrap();
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bits)).unwrap();
            assert!(MetadataDb::open(root.path()).is_err(), "{name}: {bits:o}");
        }
    }
    let root = private_dir();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o2700)).unwrap();
    assert!(MetadataDb::open(root.path()).is_err());
}

#[test]
fn open_existing_never_initializes_missing_store() {
    let root = private_dir();
    assert!(MetadataDb::open_existing(root.path()).is_err());
    assert!(!root.path().join("metadata.sqlite3").exists());
    assert!(!root.path().join("metadata.lock").exists());
    drop(MetadataDb::open(root.path()).unwrap());
    assert_eq!(
        MetadataDb::open_existing(root.path())
            .unwrap()
            .schema_version()
            .unwrap(),
        4
    );
}
#[test]
fn open_existing_rejects_missing_lock_and_initialization_marker() {
    let root = private_dir();
    drop(MetadataDb::open(root.path()).unwrap());
    std::fs::remove_file(root.path().join("metadata.lock")).unwrap();
    assert!(MetadataDb::open_existing(root.path()).is_err());
    assert!(!root.path().join("metadata.lock").exists());
    let root = private_dir();
    let marker = root.path().join("metadata.initializing");
    std::fs::write(&marker, b"dich-metadata-init-v1\n").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(MetadataDb::open_existing(root.path()).is_err());
    assert!(!root.path().join("metadata.sqlite3").exists());
}

#[test]
fn open_existing_does_not_upgrade_older_schema() {
    let root = private_dir();
    let path = root.path().join("metadata.sqlite3");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE publication_intents (object_id TEXT PRIMARY KEY NOT NULL, stage_name TEXT NOT NULL, created_at INTEGER NOT NULL); PRAGMA application_id = 1145652040; PRAGMA user_version = 1;").unwrap();
    drop(db);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let lock = root.path().join("metadata.lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(MetadataDb::open_existing(root.path()).is_err());
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1);
}
