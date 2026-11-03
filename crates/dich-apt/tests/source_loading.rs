#![cfg(target_os = "linux")]
use dich_apt::load_configured_sources;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let sources = dir.path().join("debian.sources");
    let config = dir.path().join("sources.toml");
    fs::write(&sources, include_str!("fixtures/debian.sources")).unwrap();
    let policy = include_str!("fixtures/source-policy.toml").replace(
        "/etc/dich/sources/debian.sources",
        sources.to_str().unwrap(),
    );
    fs::write(&config, policy).unwrap();
    (dir, config, sources)
}

#[test]
fn loads_enabled_sources_from_trusted_operator_files() {
    let (_dir, config, _) = setup();
    let sources = load_configured_sources(&config).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].suite(), "bookworm");
    assert_eq!(sources[0].components(), &["main", "contrib"]);
}

#[test]
fn rejects_symlinks_writable_files_and_malformed_sources() {
    let (dir, config, sources) = setup();
    let link = dir.path().join("alias.toml");
    symlink(&config, &link).unwrap();
    assert!(load_configured_sources(&link).is_err());
    fs::set_permissions(&sources, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(load_configured_sources(&config).is_err());
    fs::set_permissions(&sources, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&sources, "Types: deb\nTrusted: yes\n").unwrap();
    assert!(load_configured_sources(&config).is_err());
}
