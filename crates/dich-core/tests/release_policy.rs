use dich_core::{ArchitecturePolicy, Distribution, PolicyError};

#[test]
fn accepts_only_exact_release_and_native_or_all_architecture() {
    let policy = ArchitecturePolicy::new(Distribution::Debian, "bookworm", "amd64").unwrap();
    assert!(
        policy
            .check_source(Distribution::Debian, "bookworm", "amd64")
            .is_ok()
    );
    assert!(policy.check_package_architecture("amd64").is_ok());
    assert!(policy.check_package_architecture("all").is_ok());
    assert_eq!(
        policy.check_source(Distribution::Ubuntu, "bookworm", "amd64"),
        Err(PolicyError::DistributionMismatch)
    );
    assert_eq!(
        policy.check_source(Distribution::Debian, "trixie", "amd64"),
        Err(PolicyError::ReleaseMismatch)
    );
    assert_eq!(
        policy.check_source(Distribution::Debian, "bookworm-security", "amd64"),
        Err(PolicyError::ReleaseMismatch)
    );
    assert_eq!(
        policy.check_source(Distribution::Debian, "bookworm", "arm64"),
        Err(PolicyError::ArchitectureMismatch)
    );
    assert_eq!(
        policy.check_package_architecture("i386"),
        Err(PolicyError::ArchitectureMismatch)
    );
}

#[test]
fn rejects_aliases_wildcards_and_malformed_policy() {
    for suite in [
        "",
        "stable",
        "testing",
        "unstable",
        "oldstable",
        "stable-updates",
        "../bookworm",
        "Bookworm",
        "bookworm*",
        "a/b",
    ] {
        assert!(
            ArchitecturePolicy::new(Distribution::Debian, suite, "amd64").is_err(),
            "accepted {suite}"
        );
    }
    for arch in ["", "all", "any", "amd64 i386", "../amd64", "AMD64", "*"] {
        assert!(
            ArchitecturePolicy::new(Distribution::Debian, "bookworm", arch).is_err(),
            "accepted {arch}"
        );
    }
}
