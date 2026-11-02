#![cfg(target_os = "linux")]
use crate::cache::{CacheError, FailurePoint, SnapshotJournal, source_key};
use crate::{
    Distribution, FreshnessPolicy, SourcePolicy, ValidatedRelease, import_sources,
    validate_release, verify_configured_inrelease,
};
use std::{
    fs,
    time::{Duration, UNIX_EPOCH},
};

fn releases() -> (
    tempfile::TempDir,
    ValidatedRelease,
    ValidatedRelease,
    ValidatedRelease,
) {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let key = dir.path().join("key.gpg");
    fs::write(
        &key,
        include_bytes!("../tests/fixtures/freshness/keyring.gpg"),
    )
    .unwrap();
    let path = key.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        path,
        &["1BAC2C94BE8028EF099FD21F20B0D0ABB7CF4AFC"],
    )
    .unwrap();
    let stanza = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {path}\n"
    );
    let source = import_sources(&stanza, &policy).unwrap().remove(0);
    let signed = |input| verify_configured_inrelease(&source, input).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    let age = FreshnessPolicy::new(
        Duration::from_secs(3 * 86400),
        Duration::from_secs(86400),
        true,
    )
    .unwrap();
    let valid = validate_release(
        &signed(include_bytes!(
            "../tests/fixtures/freshness/valid.InRelease"
        )),
        now,
        age,
    )
    .unwrap();
    let equal_date_other = validate_release(
        &signed(include_bytes!(
            "../tests/fixtures/freshness/expired.InRelease"
        )),
        now,
        age,
    )
    .unwrap();
    let later_now = UNIX_EPOCH + Duration::from_secs(1_793_710_800);
    let newer = validate_release(
        &signed(include_bytes!(
            "../tests/fixtures/freshness/future.InRelease"
        )),
        later_now,
        age,
    )
    .unwrap();
    (dir, valid, equal_date_other, newer)
}

#[test]
fn rejects_equivocation_rollback_and_backwards_clock() {
    let (dir, old, equal_date_other, newer) = releases();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let first = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    let later = UNIX_EPOCH + Duration::from_secs(1_793_710_800);
    journal.record_at(&old, first, FailurePoint::None).unwrap();
    assert!(matches!(
        journal.record_at(&equal_date_other, first, FailurePoint::None),
        Err(CacheError::Equivocation)
    ));
    journal
        .record_at(&newer, later, FailurePoint::None)
        .unwrap();
    drop(journal);
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    assert!(matches!(
        journal.record_at(&old, later, FailurePoint::None),
        Err(CacheError::Rollback)
    ));
    assert!(matches!(
        journal.record_at(&newer, later - Duration::from_secs(1), FailurePoint::None),
        Err(CacheError::ClockRollback)
    ));
}

#[test]
fn failures_before_and_after_atomic_rename_do_not_accept_older_state() {
    let (dir, old, _, newer) = releases();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let first = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    let later = UNIX_EPOCH + Duration::from_secs(1_793_710_800);
    journal.record_at(&old, first, FailurePoint::None).unwrap();
    assert!(
        journal
            .record_at(&newer, later, FailurePoint::BeforeRename)
            .is_err()
    );
    journal.record_at(&old, later, FailurePoint::None).unwrap();
    assert!(
        journal
            .record_at(&newer, later, FailurePoint::AfterRename)
            .is_err()
    );
    assert!(matches!(
        journal.record_at(&old, later, FailurePoint::None),
        Err(CacheError::Rollback)
    ));
    journal
        .record_at(&newer, later, FailurePoint::None)
        .unwrap();
}

#[test]
fn rejects_corrupt_state_and_concurrent_writer() {
    use rustix::fs::{FlockOperation, flock};
    let (dir, release, _, _) = releases();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    journal
        .record_at(&release, now, FailurePoint::None)
        .unwrap();
    let name = source_key(release.source()).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join(format!("{name}.lock")))
        .unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(matches!(
        journal.record_at(&release, now, FailurePoint::None),
        Err(CacheError::Busy)
    ));
    drop(lock);
    fs::write(dir.path().join(format!("{name}.state")), b"corrupt").unwrap();
    assert!(matches!(
        journal.record_at(&release, now, FailurePoint::None),
        Err(CacheError::Corrupt)
    ));
}

#[test]
fn rejects_symlinked_or_writable_cache_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (dir, _, _, _) = releases();
    let child = dir.path().join("cache");
    fs::create_dir(&child).unwrap();
    let link = dir.path().join("link");
    symlink(&child, &link).unwrap();
    assert!(SnapshotJournal::open(&link).is_err());
    fs::set_permissions(&child, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(SnapshotJournal::open(&child).is_err());
    assert!(SnapshotJournal::open(std::path::Path::new("/")).is_err());
}

#[test]
fn rejects_symlink_state_and_hardlinked_lock() {
    use std::os::unix::fs::symlink;
    let (dir, release, _, _) = releases();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    let key = source_key(release.source()).unwrap();
    let victim = dir.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();
    symlink(&victim, dir.path().join(format!("{key}.state"))).unwrap();
    assert!(
        journal
            .record_at(&release, now, FailurePoint::None)
            .is_err()
    );
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    fs::hard_link(
        dir.path().join(format!("{key}.lock")),
        dir.path().join("other-lock"),
    )
    .unwrap();
    assert!(matches!(
        journal.record_at(&release, now, FailurePoint::None),
        Err(CacheError::UnsafePath)
    ));
}

#[test]
fn trust_rotation_and_component_narrowing_do_not_reset_floor_identity() {
    let (_dir, release, _, _) = releases();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://EXAMPLE.org:443/debian/",
        "bookworm",
        &["main", "contrib"],
        "amd64",
        "/different-key.gpg",
        &["2222222222222222222222222222222222222222"],
    )
    .unwrap();
    let source = import_sources("Types: deb\nURIs: https://EXAMPLE.org:443/debian/\nSuites: bookworm\nComponents: main contrib\nSigned-By: /different-key.gpg\n", &policy).unwrap().remove(0);
    assert_eq!(
        source_key(release.source()).unwrap(),
        source_key(&source).unwrap()
    );
}
