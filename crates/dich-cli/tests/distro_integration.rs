#![cfg(target_os = "linux")]
use dich_core::{ArchitecturePolicy, Distribution};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn test_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn write_source_config(
    dir: &std::path::Path,
    distro: &str,
    suite: &str,
    arch: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let keyring = dir.join("keyring.gpg");
    fs::write(&keyring, b"fake keyring bytes").unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();

    let uri = if distro == "debian" {
        "https://deb.debian.org/debian"
    } else {
        "https://archive.ubuntu.com/ubuntu"
    };

    let sources_file = dir.join(format!("{distro}_{suite}.sources"));
    fs::write(
        &sources_file,
        format!(
            "Types: deb\nURIs: {uri}\nSuites: {suite}\nComponents: main\nArchitectures: {arch}\nSigned-By: {}\n",
            keyring.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&sources_file, fs::Permissions::from_mode(0o600)).unwrap();

    let config = dir.join(format!("{distro}_{suite}.toml"));
    fs::write(
        &config,
        format!(
            "[[sources]]\ndistribution = \"{distro}\"\nsources_file = \"{}\"\nuri = \"{uri}\"\nsuite = \"{suite}\"\ncomponents = [\"main\"]\narchitecture = \"{arch}\"\nkeyring = \"{}\"\nfingerprints = [\"0000000000000000000000000000000000000000\"]\n",
            sources_file.display(),
            keyring.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    (config, sources_file)
}

#[test]
fn debian_bookworm_and_trixie_sources_pass_policy() {
    let temp = test_dir();
    for suite in ["bookworm", "trixie"] {
        let (config, _) = write_source_config(temp.path(), "debian", suite, "amd64");
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "--json",
                "sources",
                "list",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Sources list failed for Debian {suite}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["sources"][0]["distribution"], "debian");
        assert_eq!(json["sources"][0]["suite"], suite);
        assert_eq!(json["sources"][0]["architecture"], "amd64");
    }
}

#[test]
fn ubuntu_jammy_and_noble_sources_pass_policy() {
    let temp = test_dir();
    for suite in ["jammy", "noble"] {
        let (config, _) = write_source_config(temp.path(), "ubuntu", suite, "amd64");
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "--json",
                "sources",
                "list",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Sources list failed for Ubuntu {suite}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["sources"][0]["distribution"], "ubuntu");
        assert_eq!(json["sources"][0]["suite"], suite);
        assert_eq!(json["sources"][0]["architecture"], "amd64");
    }
}

#[test]
fn moving_suite_aliases_are_rejected_by_policy() {
    let moving_aliases = [
        "stable",
        "oldstable",
        "testing",
        "unstable",
        "sid",
        "devel",
        "rolling",
    ];

    for alias in moving_aliases {
        let res = ArchitecturePolicy::new(Distribution::Debian, alias, "amd64");
        assert!(
            res.is_err(),
            "ArchitecturePolicy should reject moving alias '{alias}'"
        );
    }
}

#[test]
fn unsupported_foreign_architectures_are_rejected_by_policy() {
    let foreign_archs = ["arm64", "i386", "armhf", "riscv64", "s390x", "ppc64el"];
    let policy = ArchitecturePolicy::new(Distribution::Debian, "bookworm", "amd64").unwrap();

    for arch in foreign_archs {
        let check = policy.check_source(Distribution::Debian, "bookworm", arch);
        assert!(
            check.is_err(),
            "Policy should reject foreign architecture '{arch}' when configured for amd64"
        );
    }
}

#[test]
fn cross_distribution_mixing_is_rejected_by_policy() {
    let debian_policy = ArchitecturePolicy::new(Distribution::Debian, "bookworm", "amd64").unwrap();
    let ubuntu_check = debian_policy.check_source(Distribution::Ubuntu, "bookworm", "amd64");
    assert!(
        ubuntu_check.is_err(),
        "Debian policy should reject Ubuntu source"
    );

    let ubuntu_policy = ArchitecturePolicy::new(Distribution::Ubuntu, "noble", "amd64").unwrap();
    let debian_check = ubuntu_policy.check_source(Distribution::Debian, "noble", "amd64");
    assert!(
        debian_check.is_err(),
        "Ubuntu policy should reject Debian source"
    );
}

#[test]
fn cross_suite_mixing_is_rejected_by_policy() {
    let policy = ArchitecturePolicy::new(Distribution::Debian, "bookworm", "amd64").unwrap();
    let trixie_check = policy.check_source(Distribution::Debian, "trixie", "amd64");
    assert!(
        trixie_check.is_err(),
        "Bookworm policy should reject Trixie source"
    );
}
