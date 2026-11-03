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
        &["F54741F2B0E1F1B32F7EE55EC9079FF55FECB8D2"],
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
    let result = journal.record_at(&equal_date_other, first, FailurePoint::None);
    assert!(
        matches!(result, Err(CacheError::Equivocation)),
        "{result:?}"
    );
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
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(rustix::io::Errno::AGAIN) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => panic!("failed to acquire test lock: {error}"),
        }
    }
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
#[ignore = "subprocess helper for cross-process lock test"]
fn child_holds_source_lock() {
    use rustix::fs::{FlockOperation, flock};
    use std::io::{BufRead, Write};
    let path = std::env::var_os("DICH_TEST_LOCK_PATH").unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    flock(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
    println!("DICH_LOCK_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
}

#[test]
fn source_lock_excludes_a_second_process() {
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
    };
    let (dir, release, _, _) = releases();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    journal
        .record_at(&release, now, FailurePoint::None)
        .unwrap();
    let name = source_key(release.source()).unwrap();
    let mut child = Command::new(std::env::args_os().next().unwrap())
        .args([
            "--ignored",
            "--exact",
            "cache_tests::child_holds_source_lock",
            "--nocapture",
        ])
        .env(
            "DICH_TEST_LOCK_PATH",
            dir.path().join(format!("{name}.lock")),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        if line.contains("DICH_LOCK_READY") {
            break;
        }
    }
    assert!(matches!(
        journal.record_at(&release, now, FailurePoint::None),
        Err(CacheError::Busy)
    ));
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(child.wait().unwrap().success());
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

fn artifact_fixture() -> (
    tempfile::TempDir,
    crate::AuthorizedArtifact,
    crate::VerifiedArtifact,
) {
    use crate::artifact::verify_artifact_stream_with_clock;
    use crate::{IndexFormat, authorize_artifact, select_indexed_artifact, verify_packages_index};
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let key = dir.path().join("key.gpg");
    fs::write(&key, include_bytes!("../tests/fixtures/index/keyring.gpg")).unwrap();
    let path = key.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        path,
        &["9DDAB0BA30893BBE88A2E583BBBAC55DCA1F9AA8"],
    )
    .unwrap();
    let stanza = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {path}\n"
    );
    let source = import_sources(&stanza, &policy).unwrap().remove(0);
    let release =
        verify_configured_inrelease(&source, include_bytes!("../tests/fixtures/index/InRelease"))
            .unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let fresh = validate_release(
        &release,
        now,
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap(),
    )
    .unwrap();
    let index = verify_packages_index(
        &release,
        "main",
        IndexFormat::Gzip,
        include_bytes!("../tests/fixtures/index/Packages.gz"),
    )
    .unwrap();
    let metadata = select_indexed_artifact(&index, "fixture", "1.0-1").unwrap();
    let authorized = authorize_artifact(&fresh, &metadata, now).unwrap();
    let verified = verify_artifact_stream_with_clock(
        &authorized,
        include_bytes!("../tests/fixtures/index/fixture.deb").as_slice(),
        1024,
        || now,
    )
    .unwrap();
    (dir, authorized, verified)
}

#[test]
fn caches_verified_artifact_and_rechecks_integrity_on_read() {
    use std::io::Read;
    let (dir, authorized, verified) = artifact_fixture();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    journal
        .store_artifact_at(&authorized, verified, now, FailurePoint::None)
        .unwrap();
    let mut result = journal.load_artifact_at(&authorized, now).unwrap();
    let mut bytes = Vec::new();
    result.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, include_bytes!("../tests/fixtures/index/fixture.deb"));
    let name = format!(
        "blob-{}",
        authorized
            .artifact()
            .sha256()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let path = dir.path().join(name);
    let mut corrupted = fs::read(&path).unwrap();
    corrupted[0] ^= 1;
    fs::write(path, corrupted).unwrap();
    assert!(journal.load_artifact_at(&authorized, now).is_err());
}

#[test]
fn cached_artifact_rejects_keyring_replacement() {
    let (dir, authorized, verified) = artifact_fixture();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    journal
        .store_artifact_at(&authorized, verified, now, FailurePoint::None)
        .unwrap();
    fs::write(
        authorized.release().source().keyring(),
        include_bytes!("../tests/fixtures/fixture-keyring.gpg"),
    )
    .unwrap();
    assert!(matches!(
        journal.load_artifact_at(&authorized, now),
        Err(CacheError::Authentication)
    ));
}

#[test]
fn artifact_publication_failures_never_expose_partial_data() {
    let (dir, authorized, verified) = artifact_fixture();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    assert!(
        journal
            .store_artifact_at(
                &authorized,
                verified,
                now,
                FailurePoint::ArtifactBeforeRename
            )
            .is_err()
    );
    assert!(journal.load_artifact_at(&authorized, now).is_err());
    let verified = crate::artifact::verify_artifact_stream_with_clock(
        &authorized,
        include_bytes!("../tests/fixtures/index/fixture.deb").as_slice(),
        1024,
        || now,
    )
    .unwrap();
    assert!(
        journal
            .store_artifact_at(
                &authorized,
                verified,
                now,
                FailurePoint::ArtifactAfterRename
            )
            .is_err()
    );
    assert!(journal.load_artifact_at(&authorized, now).is_ok());
}

#[test]
fn cached_release_is_reverified_and_expiry_is_enforced() {
    let (dir, release, _, _) = releases();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    let policy = FreshnessPolicy::new(
        Duration::from_secs(3 * 86400),
        Duration::from_secs(86400),
        true,
    )
    .unwrap();
    journal
        .store_release_at(&release, now, FailurePoint::None)
        .unwrap();
    assert!(
        journal
            .load_release_at(release.source(), policy, now)
            .is_ok()
    );
    assert!(
        journal
            .load_release_at(
                release.source(),
                policy,
                now + Duration::from_secs(3 * 86400)
            )
            .is_err()
    );
    let name = crate::cache::release_name(release.source(), release.release().contents()).unwrap();
    let path = dir.path().join(name);
    let mut bytes = fs::read(&path).unwrap();
    let pos = bytes.windows(6).position(|w| w == b"Debian").unwrap();
    bytes[pos] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(
        journal
            .load_release_at(release.source(), policy, now)
            .is_err()
    );
}

#[test]
fn caches_and_reauthenticates_detached_release_signature() {
    let (dir, release, _, _) = releases();
    let source = release.source();
    let signed = crate::verify_configured_detached_release(
        source,
        include_bytes!("../tests/fixtures/freshness/valid.Release"),
        include_bytes!("../tests/fixtures/freshness/valid.Release.gpg"),
    )
    .unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    let policy = FreshnessPolicy::new(
        Duration::from_secs(3 * 86400),
        Duration::from_secs(86400),
        true,
    )
    .unwrap();
    let validated = validate_release(&signed, now, policy).unwrap();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    journal
        .store_release_at(&validated, now, FailurePoint::None)
        .unwrap();
    let loaded = journal.load_release_at(source, policy, now).unwrap();
    assert_eq!(loaded.release().contents(), signed.contents());
}

#[test]
fn release_cache_failure_injection_never_returns_unsigned_or_partial_metadata() {
    let (dir, release, _, _) = releases();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_621_400);
    let policy = FreshnessPolicy::new(
        Duration::from_secs(3 * 86400),
        Duration::from_secs(86400),
        true,
    )
    .unwrap();
    assert!(
        journal
            .store_release_at(&release, now, FailurePoint::ReleaseBeforeRename)
            .is_err()
    );
    assert!(
        journal
            .load_release_at(release.source(), policy, now)
            .is_err()
    );
    assert!(
        journal
            .store_release_at(&release, now, FailurePoint::ReleaseAfterRename)
            .is_err()
    );
    journal
        .load_release_at(release.source(), policy, now)
        .unwrap();
}

#[test]
fn caches_index_only_after_release_reverification_and_rechecks_hash_on_read() {
    use crate::{IndexFormat, IndexLimits};
    let (dir, authorized, _) = artifact_fixture();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let policy =
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap();
    journal
        .store_release_at(authorized.release(), now, FailurePoint::None)
        .unwrap();
    journal
        .store_index_at(
            authorized.release(),
            "main",
            IndexFormat::Gzip,
            include_bytes!("../tests/fixtures/index/Packages.gz"),
            IndexLimits::default(),
            now,
            FailurePoint::None,
        )
        .unwrap();
    let (release, index) = journal
        .load_index_at(
            authorized.release().source(),
            policy,
            "main",
            IndexFormat::Gzip,
            IndexLimits::default(),
            now,
        )
        .unwrap();
    let artifact = crate::select_indexed_artifact(&index, "fixture", "1.0-1").unwrap();
    assert!(crate::authorize_artifact(&release, &artifact, now).is_ok());
    let name = crate::cache::index_name(
        authorized.release().source(),
        authorized.release().release().contents(),
        "main",
        IndexFormat::Gzip,
    )
    .unwrap();
    let path = dir.path().join(name);
    let mut bytes = fs::read(&path).unwrap();
    bytes[10] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(
        journal
            .load_index_at(
                authorized.release().source(),
                policy,
                "main",
                IndexFormat::Gzip,
                IndexLimits::default(),
                now
            )
            .is_err()
    );
}

#[test]
fn index_publication_failure_never_exposes_partial_data() {
    use crate::{IndexFormat, IndexLimits};
    let (dir, authorized, _) = artifact_fixture();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let policy =
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap();
    let input = include_bytes!("../tests/fixtures/index/Packages.gz");
    journal
        .store_release_at(authorized.release(), now, FailurePoint::None)
        .unwrap();
    assert!(
        journal
            .store_index_at(
                authorized.release(),
                "main",
                IndexFormat::Gzip,
                input,
                IndexLimits::default(),
                now,
                FailurePoint::IndexBeforeRename
            )
            .is_err()
    );
    assert!(
        journal
            .load_index_at(
                authorized.release().source(),
                policy,
                "main",
                IndexFormat::Gzip,
                IndexLimits::default(),
                now
            )
            .is_err()
    );
    assert!(
        journal
            .store_index_at(
                authorized.release(),
                "main",
                IndexFormat::Gzip,
                input,
                IndexLimits::default(),
                now,
                FailurePoint::IndexAfterRename
            )
            .is_err()
    );
    assert!(
        journal
            .load_index_at(
                authorized.release().source(),
                policy,
                "main",
                IndexFormat::Gzip,
                IndexLimits::default(),
                now
            )
            .is_ok()
    );
}

#[test]
fn fetch_rejects_equivocated_snapshot_before_any_network_request() {
    use crate::transport::{FetchError, NetworkResponse, Transport};
    struct Deny {
        calls: usize,
    }
    impl Transport for Deny {
        fn request(&mut self, _: &url::Url, _: Duration) -> Result<NetworkResponse, FetchError> {
            self.calls += 1;
            Err(FetchError::Transport)
        }
    }
    let (dir, authorized, _) = artifact_fixture();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let policy =
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap();
    let alternate = verify_configured_inrelease(
        authorized.release().source(),
        include_bytes!("../tests/fixtures/index/Alternate.InRelease"),
    )
    .unwrap();
    let alternate = validate_release(&alternate, now, policy).unwrap();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    journal
        .record_at(&alternate, now, FailurePoint::None)
        .unwrap();
    let mut transport = Deny { calls: 0 };
    assert!(matches!(
        journal.fetch_with_transport(&authorized, 1024, &mut transport, || now),
        Err(CacheError::Equivocation)
    ));
    assert_eq!(transport.calls, 0);
}
