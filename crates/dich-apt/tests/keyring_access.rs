#![cfg(target_os = "linux")]
use dich_apt::{
    Distribution, Source, SourcePolicy, import_sources, read_configured_keyring,
    verify_configured_detached_release, verify_configured_inrelease,
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn source(path: &str) -> Source {
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        path,
        &["0123456789ABCDEF0123456789ABCDEF01234567"],
    )
    .unwrap();
    let stanza = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {path}\n"
    );
    import_sources(&stanza, &policy).unwrap().remove(0)
}

#[test]
fn verifies_using_the_keyring_at_the_configured_path() {
    let home = std::env::var_os("HOME").unwrap();
    let dir = tempfile::tempdir_in(home).unwrap();
    let path = dir.path().join("keys.gpg");
    fs::write(&path, include_bytes!("fixtures/fixture-keyring.gpg")).unwrap();
    let path_str = path.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        path_str,
        &["A85557F5D19615DCBE48C0A673D4B958454DE07D"],
    )
    .unwrap();
    let stanza = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {path_str}\n"
    );
    let source = import_sources(&stanza, &policy).unwrap().remove(0);
    assert!(verify_configured_inrelease(&source, include_bytes!("fixtures/InRelease")).is_ok());
    assert!(
        verify_configured_detached_release(
            &source,
            include_bytes!("fixtures/Release"),
            include_bytes!("fixtures/Release.gpg")
        )
        .is_ok()
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(verify_configured_inrelease(&source, include_bytes!("fixtures/InRelease")).is_err());
}

#[test]
fn reads_only_secure_regular_keyring_from_configured_path() {
    let home = std::env::var_os("HOME").expect("HOME for secure test directory");
    let dir = tempfile::tempdir_in(home).unwrap();
    let path = dir.path().join("keyring.gpg");
    fs::write(&path, b"fixture-keyring").unwrap();
    let source = source(path.to_str().unwrap());
    assert_eq!(
        read_configured_keyring(&source).unwrap(),
        b"fixture-keyring"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_configured_keyring(&source).is_err());
}

#[test]
fn rejects_symlinks_and_writable_ancestors() {
    let home = std::env::var_os("HOME").expect("HOME for secure test directory");
    let dir = tempfile::tempdir_in(home).unwrap();
    let actual = dir.path().join("actual.gpg");
    let alias = dir.path().join("alias.gpg");
    fs::write(&actual, b"fixture").unwrap();
    symlink(&actual, &alias).unwrap();
    assert!(read_configured_keyring(&source(alias.to_str().unwrap())).is_err());
    let ancestor_alias = dir.path().join("linked");
    let nested = dir.path().join("nested");
    fs::create_dir(&nested).unwrap();
    symlink(&nested, &ancestor_alias).unwrap();
    let nested_key = nested.join("key.gpg");
    fs::write(&nested_key, b"fixture").unwrap();
    assert!(
        read_configured_keyring(&source(ancestor_alias.join("key.gpg").to_str().unwrap())).is_err()
    );
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(read_configured_keyring(&source(nested_key.to_str().unwrap())).is_err());
}
