#![cfg(target_os = "linux")]
use dich_apt::{
    Distribution, FreshnessPolicy, IndexFormat, IndexLimits, SourcePolicy, authorize_artifact,
    import_sources, select_indexed_artifact, validate_release, verify_configured_inrelease,
    verify_packages_index,
};
use std::{
    fs,
    io::Read,
    time::{Duration, SystemTime},
};

#[test]
#[ignore = "requires prepared Ubuntu noble Release, compressed index, keyring and network"]
fn fetches_real_ubuntu_artifact_through_verified_chain() {
    let keyring = "/root/ubuntu-archive-keyring.gpg";
    let policy = SourcePolicy::new(
        Distribution::Ubuntu,
        "https://archive.ubuntu.com/ubuntu",
        "noble",
        &["main"],
        "amd64",
        keyring,
        &["F6ECB3762474EDA9D21B7022871920D1991BC93C"],
    )
    .unwrap();
    let stanza = format!(
        "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\nSuites: noble\nComponents: main\nArchitectures: amd64\nSigned-By: {keyring}\n"
    );
    let source = import_sources(&stanza, &policy).unwrap().remove(0);
    let signed = fs::read("/root/ubuntu-noble.InRelease").unwrap();
    let release = verify_configured_inrelease(&source, &signed).unwrap();
    // Noble's immutable initial Release has no Valid-Until. This deliberately
    // loose policy is test-only and does not prevent rollback within its window.
    let now = SystemTime::now();
    let freshness = FreshnessPolicy::new(
        Duration::from_secs(3 * 366 * 86400),
        Duration::from_secs(300),
        false,
    )
    .unwrap();
    let fresh = validate_release(&release, now, freshness).unwrap();
    let compressed = fs::read("/root/noble-Packages.xz").unwrap();
    let index = verify_packages_index(&release, "main", IndexFormat::Xz, &compressed).unwrap();
    let artifact = select_indexed_artifact(&index, "hello", "2.10-3build1").unwrap();
    let authorized = authorize_artifact(&fresh, &artifact, SystemTime::now()).unwrap();
    let cache = tempfile::tempdir_in("/root").unwrap();
    let journal = dich_apt::SnapshotJournal::open(cache.path()).unwrap();
    journal.store_release(&fresh).unwrap();
    journal
        .store_index(
            &fresh,
            "main",
            IndexFormat::Xz,
            &compressed,
            IndexLimits::default(),
        )
        .unwrap();
    let (cached_release, cached_index) = journal
        .load_index(
            &source,
            freshness,
            "main",
            IndexFormat::Xz,
            IndexLimits::default(),
        )
        .unwrap();
    let cached_artifact = select_indexed_artifact(&cached_index, "hello", "2.10-3build1").unwrap();
    assert!(authorize_artifact(&cached_release, &cached_artifact, SystemTime::now()).is_ok());
    let mut verified = journal.fetch_artifact(&authorized, 1024 * 1024).unwrap();
    let mut bytes = Vec::new();
    verified.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len(), 26006);
    assert!(bytes.starts_with(b"!<arch>\n"));
    journal.store_artifact(&authorized, verified).unwrap();
    let mut cached = journal.load_artifact(&authorized).unwrap();
    let mut from_cache = Vec::new();
    cached.read_to_end(&mut from_cache).unwrap();
    assert_eq!(from_cache, bytes);
}
