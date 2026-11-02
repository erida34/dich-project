#![cfg(target_os = "linux")]
use dich_apt::{
    Distribution, IndexFormat, IndexLimits, SourcePolicy, import_sources,
    verify_configured_inrelease, verify_packages_index, verify_packages_index_with_limits,
};
use std::fs;

const KEY: &str = "2621D0B482D3939937D9835FC2E57866B59C9D03";
const CLEAR: &[u8] = include_bytes!("fixtures/index/InRelease");
const GZIP: &[u8] = include_bytes!("fixtures/index/Packages.gz");
const XZ: &[u8] = include_bytes!("fixtures/index/Packages.xz");
const BOMB: &[u8] = include_bytes!("fixtures/index/bomb.gz");
const CONTENT: &[u8] = b"Package: fixture\nVersion: 1.0-1\nArchitecture: amd64\n\n";

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
