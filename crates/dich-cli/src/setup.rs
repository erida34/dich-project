#![forbid(unsafe_code)]

use crate::{CliError, ResolvedPaths};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DefaultSource {
    distribution: &'static str,
    suite: &'static str,
    uri: &'static str,
    keyring: &'static str,
    fingerprints: &'static [&'static str],
}

fn supported_default(id: &str, suite: &str, architecture: &str) -> Option<DefaultSource> {
    if architecture != "amd64" {
        return None;
    }
    match (id, suite) {
        ("debian", "bookworm") => Some(DefaultSource {
            distribution: "debian",
            suite: "bookworm",
            uri: "https://deb.debian.org/debian",
            keyring: "/usr/share/keyrings/debian-archive-keyring.gpg",
            fingerprints: &[
                "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8",
                "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
                "4D64FEC119C2029067D6E791F8D2585B8783D481",
            ],
        }),
        ("debian", "trixie") => Some(DefaultSource {
            distribution: "debian",
            suite: "trixie",
            uri: "https://deb.debian.org/debian",
            keyring: "/usr/share/keyrings/debian-archive-keyring.pgp",
            fingerprints: &[
                "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8",
                "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
                "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
            ],
        }),
        ("ubuntu", "jammy") => Some(DefaultSource {
            distribution: "ubuntu",
            suite: "jammy",
            uri: "https://archive.ubuntu.com/ubuntu",
            keyring: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
            fingerprints: &["F6ECB3762474EDA9D21B7022871920D1991BC93C"],
        }),
        ("ubuntu", "noble") => Some(DefaultSource {
            distribution: "ubuntu",
            suite: "noble",
            uri: "https://archive.ubuntu.com/ubuntu",
            keyring: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
            fingerprints: &["F6ECB3762474EDA9D21B7022871920D1991BC93C"],
        }),
        _ => None,
    }
}

fn detect_default(os_release: &str, architecture: &str) -> Option<DefaultSource> {
    let mut id = None;
    let mut suite = None;
    for line in os_release.lines() {
        if let Some(value) = line.strip_prefix("ID=") {
            id = Some(value.trim_matches('"'));
        } else if let Some(value) = line.strip_prefix("VERSION_CODENAME=") {
            suite = Some(value.trim_matches('"'));
        }
    }
    supported_default(id?, suite?, architecture)
}

fn config_contents(
    source: DefaultSource,
    source_file: &Path,
) -> Result<(String, String), CliError> {
    let source_file = source_file.to_str().ok_or_else(unsupported)?;
    if !source_file.is_ascii()
        || !source_file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._+-".contains(&b))
    {
        return Err(unsupported());
    }
    let fingerprints = source.fingerprints.join("\", \"");
    let toml = format!(
        "[[sources]]\ndistribution = \"{}\"\nsources_file = \"{}\"\nuri = \"{}\"\nsuite = \"{}\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"{}\"]\n",
        source.distribution, source_file, source.uri, source.suite, source.keyring, fingerprints
    );
    let deb822 = format!(
        "Types: deb\nURIs: {}\nSuites: {}\nComponents: main\nArchitectures: amd64\nSigned-By: {}\n",
        source.uri, source.suite, source.keyring
    );
    Ok((toml, deb822))
}

fn unsupported() -> CliError {
    CliError {
        code: "default_source_unsupported",
        message: "no verified default source is defined for this distribution, suite or architecture",
        trace: vec!["supported defaults: Debian 12/13 and Ubuntu 22.04/24.04 amd64".into()],
    }
}

#[cfg(target_os = "linux")]
pub(super) fn configure_defaults(paths: &ResolvedPaths) -> Result<(), CliError> {
    let os_release = fs::read_to_string("/etc/os-release").map_err(|_| unsupported())?;
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        _ => std::env::consts::ARCH,
    };
    let source = detect_default(&os_release, architecture).ok_or_else(unsupported)?;
    let config_dir = paths.config.parent().ok_or_else(unsupported)?;
    let sources_dir = config_dir.join("sources");
    if paths.is_rootless {
        crate::paths::ensure_private_directory(config_dir)?;
        crate::paths::ensure_private_directory(&sources_dir)?;
    } else {
        ensure_system_directory(config_dir)?;
        ensure_system_directory(&sources_dir)?;
    }
    let source_file = sources_dir.join("official.sources");
    let (toml, deb822) = config_contents(source, &source_file)?;
    let policies = dich_apt::parse_source_config(&toml).map_err(|_| unsupported())?;
    let parsed =
        dich_apt::import_sources(&deb822, policies[0].policy()).map_err(|_| unsupported())?;
    dich_apt::read_configured_keyring(&parsed[0]).map_err(|_| CliError {
        code: "default_keyring_unavailable",
        message: "the official distribution archive keyring is missing or unsafe",
        trace: vec![source.keyring.into()],
    })?;
    check_existing(&source_file, deb822.as_bytes())?;
    check_existing(&paths.config, toml.as_bytes())?;
    atomic_create(&source_file, deb822.as_bytes(), paths.is_rootless)?;
    atomic_create(&paths.config, toml.as_bytes(), paths.is_rootless)?;
    if dich_apt::load_configured_sources(&paths.config).is_err() {
        return Err(CliError {
            code: "default_source_invalid",
            message: "generated source configuration failed validation; no repository was contacted",
            trace: vec![
                "check that the distribution archive keyring is installed and protected".into(),
            ],
        });
    }
    if !paths.is_rootless {
        println!(
            "completed: default policy created for official {} {}; signatures are checked by update",
            source.distribution, source.suite
        );
    } else {
        println!(
            "completed: default policy for official {} {} created at {}; signatures are checked by update",
            source.distribution,
            source.suite,
            paths.config.display()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn configure_defaults(_: &ResolvedPaths) -> Result<(), CliError> {
    Err(CliError {
        code: "unsupported_platform",
        message: "default source setup requires Linux",
        trace: Vec::new(),
    })
}

#[cfg(target_os = "linux")]
fn ensure_system_directory(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(unsafe_dir(path));
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
                    .map_err(|_| unsafe_dir(&current))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(unsafe_dir(&current)),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| unsafe_dir(&current))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(unsafe_dir(&current));
        }
    }
    Ok(())
}

fn unsafe_dir(path: &Path) -> CliError {
    CliError {
        code: "unsafe_config_directory",
        message: "configuration directory is not a protected root-owned directory",
        trace: vec![path.display().to_string()],
    }
}

fn atomic_create(path: &Path, contents: &[u8], rootless: bool) -> Result<(), CliError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if path.exists() {
        return match fs::read(path) {
            Ok(existing) if existing == contents => Ok(()),
            _ => Err(CliError {
                code: "config_exists",
                message: "configuration already exists and was left unchanged",
                trace: vec![path.display().to_string()],
            }),
        };
    }
    let parent = path.parent().ok_or_else(unsupported)?;
    let suffix = format!(".tmp-{}", std::process::id());
    let mut temp = path.file_name().ok_or_else(unsupported)?.to_os_string();
    temp.push(&suffix);
    let temp_path = parent.join(temp);
    let mode = if rootless { 0o600 } else { 0o644 };
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::hard_link(&temp_path, path)?;
        fs::remove_file(&temp_path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok::<_, std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.map_err(|_| CliError {
        code: "config_write_failed",
        message: "could not create source configuration without replacing existing files",
        trace: vec![path.display().to_string()],
    })
}

fn check_existing(path: &Path, expected: &[u8]) -> Result<(), CliError> {
    if path.exists() && fs::read(path).ok().as_deref() != Some(expected) {
        return Err(CliError {
            code: "config_exists",
            message: "configuration already exists and was left unchanged",
            trace: vec![path.display().to_string()],
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_supported_official_release_matrix() {
        for (id, suite) in [
            ("debian", "bookworm"),
            ("debian", "trixie"),
            ("ubuntu", "jammy"),
            ("ubuntu", "noble"),
        ] {
            assert!(supported_default(id, suite, "amd64").is_some());
        }
        assert!(supported_default("ubuntu", "noble", "arm64").is_none());
        assert!(supported_default("ubuntu", "devel", "amd64").is_none());
        assert!(supported_default("linuxmint", "noble", "amd64").is_none());
    }

    #[test]
    fn debian_defaults_use_the_complete_regular_keyring_files() {
        assert_eq!(
            supported_default("debian", "bookworm", "amd64")
                .unwrap()
                .keyring,
            "/usr/share/keyrings/debian-archive-keyring.gpg"
        );
        assert_eq!(
            supported_default("debian", "trixie", "amd64")
                .unwrap()
                .keyring,
            "/usr/share/keyrings/debian-archive-keyring.pgp"
        );
    }

    #[test]
    fn debian_defaults_pin_all_official_signers_for_current_inrelease_files() {
        assert_eq!(
            supported_default("debian", "bookworm", "amd64")
                .unwrap()
                .fingerprints,
            &[
                "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8",
                "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
                "4D64FEC119C2029067D6E791F8D2585B8783D481",
            ]
        );
        assert_eq!(
            supported_default("debian", "trixie", "amd64")
                .unwrap()
                .fingerprints,
            &[
                "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8",
                "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
                "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
            ]
        );
    }

    #[test]
    fn generated_debian_policy_keeps_each_signer_explicitly_pinned() {
        for suite in ["bookworm", "trixie"] {
            let source = supported_default("debian", suite, "amd64").unwrap();
            let source_file = Path::new("/etc/dich/sources/official.sources");
            let (toml, deb822) = config_contents(source, source_file).unwrap();
            let configured = dich_apt::parse_source_config(&toml).unwrap();
            let imported = dich_apt::import_sources(&deb822, configured[0].policy()).unwrap();
            assert_eq!(imported[0].fingerprints(), source.fingerprints);
            assert_eq!(imported[0].keyring(), source.keyring);
        }
    }

    #[test]
    fn os_release_is_parsed_as_data_not_shell() {
        let parsed = detect_default("ID=ubuntu\nVERSION_CODENAME=noble\n", "amd64");
        assert_eq!(
            parsed.unwrap().fingerprints,
            &["F6ECB3762474EDA9D21B7022871920D1991BC93C"]
        );
        assert!(
            detect_default(
                "ID=ubuntu\nVERSION_CODENAME=jammy; touch /tmp/pwned\n",
                "amd64"
            )
            .is_none()
        );
    }

    #[test]
    fn config_creation_is_idempotent_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.toml");
        atomic_create(&path, b"trusted policy\n", true).unwrap();
        atomic_create(&path, b"trusted policy\n", true).unwrap();
        let error = atomic_create(&path, b"replacement\n", true).unwrap_err();
        assert_eq!(error.code, "config_exists");
        assert_eq!(fs::read(path).unwrap(), b"trusted policy\n");
    }
}
