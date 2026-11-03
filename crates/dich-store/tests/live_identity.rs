#![cfg(target_os = "linux")]
use dich_apt::{
    FreshnessPolicy, IndexLimits, SnapshotJournal, authorize_artifact, choose_index_format,
    load_configured_sources, select_indexed_artifact,
};
use dich_store::{
    IdentityComparison, MetadataDb, PublicationOutcome, StoreIdentity, TransformPolicy,
};
use std::{
    path::Path,
    time::{Duration, SystemTime},
};

#[test]
#[ignore = "requires the verified Ubuntu noble artifact cached by the staging integration test"]
fn identity_is_derived_from_reverified_cached_artifact() {
    let config = std::env::var("DICH_TEST_CONFIG").unwrap();
    let cache = std::env::var("DICH_TEST_CACHE").unwrap();
    let source = load_configured_sources(Path::new(&config))
        .unwrap()
        .remove(0);
    let journal = SnapshotJournal::open(Path::new(&cache)).unwrap();
    let freshness = FreshnessPolicy::new(
        Duration::from_secs(3 * 366 * 86400),
        Duration::from_secs(300),
        false,
    )
    .unwrap();
    let release = journal.load_release(&source, freshness).unwrap();
    let format = choose_index_format(&release, "main").unwrap();
    let (release, index) = journal
        .load_index(&source, freshness, "main", format, IndexLimits::default())
        .unwrap();
    let artifact = select_indexed_artifact(&index, "alsa-topology-conf", "1.2.5.1-2").unwrap();
    let authorized = authorize_artifact(&release, &artifact, SystemTime::now()).unwrap();
    let first = StoreIdentity::from_cached(
        &journal,
        &authorized,
        TransformPolicy::PrivateRegularFilesV1,
    )
    .unwrap();
    let second = StoreIdentity::from_cached(
        &journal,
        &authorized,
        TransformPolicy::PrivateRegularFilesV1,
    )
    .unwrap();
    assert_eq!(first.hex().len(), 64);
    assert_eq!(first.compare(&second), IdentityComparison::SameIdentity);
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = MetadataDb::open(root.path()).unwrap();
    let (archive_identity, outcome) = store.publish_cached_archive(&journal, &authorized).unwrap();
    assert_eq!(outcome, PublicationOutcome::Published);
    let (again, outcome) = store.publish_cached_archive(&journal, &authorized).unwrap();
    assert_eq!(outcome, PublicationOutcome::Reused);
    assert_eq!(
        archive_identity.compare(&again),
        IdentityComparison::SameIdentity
    );
    assert_ne!(archive_identity.digest(), first.digest());
}
