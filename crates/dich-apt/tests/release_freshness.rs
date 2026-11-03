#![cfg(target_os = "linux")]
use dich_apt::{
    Distribution, FreshnessPolicy, Source, SourcePolicy, import_sources, validate_release,
    verify_configured_inrelease,
};
use std::{
    fs,
    time::{Duration, UNIX_EPOCH},
};

const KEY: &str = "F54741F2B0E1F1B32F7EE55EC9079FF55FECB8D2";
const NOW: u64 = 1_793_707_200;

fn source() -> (tempfile::TempDir, Source) {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let path = dir.path().join("key.gpg");
    fs::write(&path, include_bytes!("fixtures/freshness/keyring.gpg")).unwrap();
    let path = path.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        path,
        &[KEY],
    )
    .unwrap();
    let input = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {path}\n"
    );
    (dir, import_sources(&input, &policy).unwrap().remove(0))
}

#[test]
fn accepts_fresh_signed_release_bound_to_distribution_and_suite() {
    let (_dir, source) = source();
    let release = verify_configured_inrelease(
        &source,
        include_bytes!("fixtures/freshness/valid.InRelease"),
    )
    .unwrap();
    let policy = FreshnessPolicy::new(
        Duration::from_secs(2 * 86400),
        Duration::from_secs(300),
        true,
    )
    .unwrap();
    assert!(validate_release(&release, UNIX_EPOCH + Duration::from_secs(NOW), policy).is_ok());
}

#[test]
fn rejects_expired_future_wrong_suite_or_origin() {
    let (_dir, source) = source();
    let policy = FreshnessPolicy::new(
        Duration::from_secs(2 * 86400),
        Duration::from_secs(300),
        true,
    )
    .unwrap();
    for input in [
        include_bytes!("fixtures/freshness/expired.InRelease").as_slice(),
        include_bytes!("fixtures/freshness/future.InRelease").as_slice(),
        include_bytes!("fixtures/freshness/wrong-suite.InRelease").as_slice(),
        include_bytes!("fixtures/freshness/wrong-origin.InRelease").as_slice(),
        include_bytes!("fixtures/freshness/missing.InRelease").as_slice(),
    ] {
        let release = verify_configured_inrelease(&source, input).unwrap();
        assert!(validate_release(&release, UNIX_EPOCH + Duration::from_secs(NOW), policy).is_err());
    }
}

#[test]
fn permits_missing_valid_until_only_with_explicit_max_age() {
    let (_dir, source) = source();
    let release = verify_configured_inrelease(
        &source,
        include_bytes!("fixtures/freshness/missing.InRelease"),
    )
    .unwrap();
    let policy = FreshnessPolicy::new(
        Duration::from_secs(2 * 86400),
        Duration::from_secs(300),
        false,
    )
    .unwrap();
    assert!(validate_release(&release, UNIX_EPOCH + Duration::from_secs(NOW), policy).is_ok());
    assert!(
        validate_release(
            &release,
            UNIX_EPOCH + Duration::from_secs(NOW + 2 * 86400),
            policy
        )
        .is_err()
    );
    assert!(FreshnessPolicy::new(Duration::ZERO, Duration::ZERO, false).is_err());
}

#[test]
fn authenticated_release_obeys_explicit_resolver_policy() {
    let (_dir, source) = source();
    let verified = verify_configured_inrelease(
        &source,
        include_bytes!("fixtures/freshness/valid.InRelease"),
    )
    .unwrap();
    let freshness = FreshnessPolicy::new(
        Duration::from_secs(2 * 86400),
        Duration::from_secs(300),
        true,
    )
    .unwrap();
    let release =
        validate_release(&verified, UNIX_EPOCH + Duration::from_secs(NOW), freshness).unwrap();
    let policy =
        dich_core::ArchitecturePolicy::new(dich_core::Distribution::Debian, "bookworm", "amd64")
            .unwrap();
    assert!(dich_apt::check_release_policy(&policy, &release).is_ok());
    for policy in [
        dich_core::ArchitecturePolicy::new(dich_core::Distribution::Ubuntu, "bookworm", "amd64")
            .unwrap(),
        dich_core::ArchitecturePolicy::new(dich_core::Distribution::Debian, "trixie", "amd64")
            .unwrap(),
        dich_core::ArchitecturePolicy::new(dich_core::Distribution::Debian, "bookworm", "arm64")
            .unwrap(),
    ] {
        assert!(dich_apt::check_release_policy(&policy, &release).is_err());
    }
}
