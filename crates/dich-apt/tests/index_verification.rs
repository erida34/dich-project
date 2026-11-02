#![cfg(target_os = "linux")]
use dich_apt::{
    Distribution, FreshnessPolicy, IndexFormat, IndexLimits, SourcePolicy, authorize_artifact,
    import_sources, select_indexed_artifact, validate_release, verify_configured_inrelease,
    verify_packages_index, verify_packages_index_with_limits,
};
use std::{
    fs,
    time::{Duration, UNIX_EPOCH},
};

const KEY: &str = "9DDAB0BA30893BBE88A2E583BBBAC55DCA1F9AA8";
const CLEAR: &[u8] = include_bytes!("fixtures/index/InRelease");
const GZIP: &[u8] = include_bytes!("fixtures/index/Packages.gz");
const XZ: &[u8] = include_bytes!("fixtures/index/Packages.xz");
const BOMB: &[u8] = include_bytes!("fixtures/index/bomb.gz");
const CONTENT: &[u8] = include_bytes!("fixtures/index/Packages");

#[test]
fn selects_only_artifacts_from_authenticated_index_metadata() {
    let (_dir, release) = verified_release();
    let index = verify_packages_index(&release, "main", IndexFormat::Gzip, GZIP).unwrap();
    let artifact = select_indexed_artifact(&index, "fixture", "1.0-1").unwrap();
    assert_eq!(
        artifact.path(),
        "pool/main/f/fixture/fixture_1.0-1_amd64.deb"
    );
    assert_eq!(
        artifact.size(),
        include_bytes!("fixtures/index/fixture.deb").len() as u64
    );
    assert!(select_indexed_artifact(&index, "fixture", "1.0-2").is_err());
    assert!(select_indexed_artifact(&index, "../fixture", "1.0-1").is_err());
}

#[test]
fn artifact_authorization_requires_fresh_same_release() {
    let (_dir, release) = verified_release();
    let index = verify_packages_index(&release, "main", IndexFormat::Gzip, GZIP).unwrap();
    let artifact = select_indexed_artifact(&index, "fixture", "1.0-1").unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let policy = FreshnessPolicy::new(
        Duration::from_secs(2 * 86400),
        Duration::from_secs(300),
        true,
    )
    .unwrap();
    let fresh = validate_release(&release, now, policy).unwrap();
    assert!(authorize_artifact(&fresh, &artifact, now).is_ok());
    assert!(authorize_artifact(&fresh, &artifact, now + Duration::from_secs(2 * 86400)).is_err());
    let alternate = verify_configured_inrelease(
        release.source(),
        include_bytes!("fixtures/index/Alternate.InRelease"),
    )
    .unwrap();
    let alternate = validate_release(&alternate, now, policy).unwrap();
    assert!(authorize_artifact(&alternate, &artifact, now).is_err());
}

fn verified_release() -> (tempfile::TempDir, dich_apt::VerifiedRelease) {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let key = dir.path().join("index-keyring.gpg");
    fs::write(&key, include_bytes!("fixtures/index/keyring.gpg")).unwrap();
    let key = key.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main", "bomb", "broken", "trailing"],
        "amd64",
        key,
        &[KEY],
    )
    .unwrap();
    let input = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main bomb broken trailing\nArchitectures: amd64\nSigned-By: {key}\n"
    );
    let source = import_sources(&input, &policy).unwrap().remove(0);
    let verified = verify_configured_inrelease(&source, CLEAR).unwrap();
    (dir, verified)
}

#[test]
fn verifies_signed_index_digest_before_decompression() {
    let (_dir, release) = verified_release();
    for (format, compressed) in [(IndexFormat::Gzip, GZIP), (IndexFormat::Xz, XZ)] {
        assert_eq!(
            verify_packages_index(&release, "main", format, compressed)
                .unwrap()
                .contents(),
            CONTENT
        );
    }
}

#[test]
fn rejects_mismatch_truncation_unapproved_paths_and_bomb() {
    let (_dir, release) = verified_release();
    let mut modified = GZIP.to_vec();
    modified[10] ^= 1;
    assert!(verify_packages_index(&release, "main", IndexFormat::Gzip, &modified).is_err());
    assert!(
        verify_packages_index(&release, "main", IndexFormat::Gzip, &GZIP[..GZIP.len() - 1])
            .is_err()
    );
    assert!(verify_packages_index(&release, "main", IndexFormat::Xz, GZIP).is_err());
    assert!(verify_packages_index(&release, "../main", IndexFormat::Gzip, GZIP).is_err());
    assert!(verify_packages_index(&release, "contrib", IndexFormat::Gzip, GZIP).is_err());
    let limits = IndexLimits::new(32 * 1024 * 1024, 16 * 1024 * 1024).unwrap();
    assert!(
        verify_packages_index_with_limits(&release, "bomb", IndexFormat::Gzip, BOMB, limits)
            .is_err()
    );
    assert!(
        verify_packages_index_with_limits(
            &release,
            "bomb",
            IndexFormat::Xz,
            include_bytes!("fixtures/index/bomb.xz"),
            limits
        )
        .is_err()
    );
    assert!(
        verify_packages_index(
            &release,
            "broken",
            IndexFormat::Gzip,
            include_bytes!("fixtures/index/broken.gz")
        )
        .is_err()
    );
    assert!(
        verify_packages_index(
            &release,
            "broken",
            IndexFormat::Xz,
            include_bytes!("fixtures/index/broken.xz")
        )
        .is_err()
    );
    assert!(
        verify_packages_index(
            &release,
            "trailing",
            IndexFormat::Gzip,
            include_bytes!("fixtures/index/trailing.gz")
        )
        .is_err()
    );
}
