#![cfg(target_os = "linux")]
use crate::artifact::verify_artifact_stream_with_clock;
use crate::{
    Distribution, FreshnessPolicy, IndexFormat, SourcePolicy, authorize_artifact, import_sources,
    select_indexed_artifact, validate_release, verify_configured_inrelease, verify_packages_index,
};
use std::{
    fs,
    io::Read,
    time::{Duration, UNIX_EPOCH},
};

#[test]
fn verifies_stream_size_digest_and_freshness_before_return() {
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
    let bytes = include_bytes!("../tests/fixtures/index/fixture.deb");
    let mut verified =
        verify_artifact_stream_with_clock(&authorized, bytes.as_slice(), 1024, || now).unwrap();
    let mut actual = Vec::new();
    verified.read_to_end(&mut actual).unwrap();
    assert_eq!(&actual, bytes);
    assert!(
        verify_artifact_stream_with_clock(&authorized, &bytes[..bytes.len() - 1], 1024, || now)
            .is_err()
    );
    assert!(
        verify_artifact_stream_with_clock(
            &authorized,
            &[bytes.as_slice(), b"x"].concat()[..],
            1024,
            || now
        )
        .is_err()
    );
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    assert!(
        verify_artifact_stream_with_clock(&authorized, changed.as_slice(), 1024, || now).is_err()
    );
    let calls = std::cell::Cell::new(0);
    assert!(
        verify_artifact_stream_with_clock(&authorized, bytes.as_slice(), 1024, || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                now
            } else {
                now + Duration::from_secs(2 * 86400)
            }
        })
        .is_err()
    );
    assert!(verify_artifact_stream_with_clock(&authorized, bytes.as_slice(), 1, || now).is_err());
}
