use dich_apt::{Distribution, SourceError, SourcePolicy, import_sources};

const KEY: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
const OTHER_KEY: &str = "1111111111111111111111111111111111111111";
const FIXTURE: &str = include_str!("fixtures/debian.sources");

fn policy() -> SourcePolicy {
    SourcePolicy::new(
        Distribution::Debian,
        "https://deb.debian.org/debian",
        "bookworm",
        &["main", "contrib"],
        "amd64",
        "/usr/share/keyrings/debian-archive-keyring.pgp",
        &[KEY],
    )
    .unwrap()
}

#[test]
fn imports_deb822_with_explicit_policy_and_folded_components() {
    let sources = import_sources(FIXTURE, &policy()).unwrap();
    assert_eq!(sources.len(), 1);
    let source = &sources[0];
    assert_eq!(source.distribution(), Distribution::Debian);
    assert_eq!(source.uri(), "https://deb.debian.org/debian");
    assert_eq!(source.suite(), "bookworm");
    assert_eq!(source.components(), &["main", "contrib"]);
    assert_eq!(source.architecture(), "amd64");
    assert_eq!(
        source.keyring(),
        "/usr/share/keyrings/debian-archive-keyring.pgp"
    );
    assert_eq!(source.fingerprints(), &[KEY]);
}

#[test]
fn rejects_source_options_that_relax_or_change_policy() {
    let cases = [
        FIXTURE.replace(
            "https://deb.debian.org/debian",
            "https://evil.example/debian",
        ),
        FIXTURE.replace("bookworm", "trixie"),
        FIXTURE.replace("contrib", "non-free"),
        FIXTURE.replace("amd64", "arm64"),
        FIXTURE.replace(
            "/usr/share/keyrings/debian-archive-keyring.pgp",
            "/tmp/other.gpg",
        ),
        FIXTURE.replace("Signed-By:", "Trusted: yes\nSigned-By:"),
        FIXTURE.replace("Types: deb", "Types: deb-src"),
        FIXTURE.replace("Signed-By:", "Signed-By: /tmp/a\nSigned-By:"),
        FIXTURE.replace(
            "Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp",
            "",
        ),
        format!("{FIXTURE} {OTHER_KEY}\n"),
    ];
    for input in cases {
        assert!(
            import_sources(&input, &policy()).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn handles_disabled_stanzas_and_rejects_malformed_or_unbounded_input() {
    assert!(
        import_sources(&format!("Enabled: no\n{FIXTURE}"), &policy())
            .unwrap()
            .is_empty()
    );
    assert!(import_sources(&format!("Enabled: maybe\n{FIXTURE}"), &policy()).is_err());
    assert!(import_sources(&format!(" orphan\n{FIXTURE}"), &policy()).is_err());
    assert!(matches!(
        import_sources(&"x".repeat(1_048_577), &policy()),
        Err(SourceError::InputTooLarge)
    ));
}

#[test]
fn multiple_stanzas_and_fingerprint_restriction() {
    let source = FIXTURE.replace(
        "debian-archive-keyring.pgp",
        &format!("debian-archive-keyring.pgp {}", KEY.to_ascii_lowercase()),
    );
    let two = format!("{source}\n{source}");
    let parsed = import_sources(&two, &policy()).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].fingerprints(), &[KEY]);
    let no_arch = source.replace("Architectures: amd64\n", "");
    assert_eq!(
        import_sources(&no_arch, &policy()).unwrap()[0].architecture(),
        "amd64"
    );
}

#[test]
fn refuses_excessive_values_and_invalid_fields() {
    let excessive = FIXTURE.replace(
        "Components: main\n contrib",
        &format!("Components: {}", "main ".repeat(129)),
    );
    assert!(import_sources(&excessive, &policy()).is_err());
    assert!(import_sources(&format!("{FIXTURE}\nBad-Option: yes\n"), &policy()).is_err());
    assert!(import_sources(&format!("{FIXTURE}\0"), &policy()).is_err());
    assert!(import_sources(&format!("{FIXTURE}\n").repeat(257), &policy()).is_err());
}

#[test]
fn rejects_invalid_operator_policy() {
    for uri in [
        "http://example.org",
        "https://user@example.org",
        "https://example.org/a/../b",
        "https://example.org/%2e%2e",
    ] {
        assert!(
            SourcePolicy::new(
                Distribution::Debian,
                uri,
                "bookworm",
                &["main"],
                "amd64",
                "/key.gpg",
                &[KEY]
            )
            .is_err()
        );
    }
    assert!(
        SourcePolicy::new(
            Distribution::Debian,
            "https://example.org",
            "bookworm",
            &["main"],
            "amd64",
            "relative.gpg",
            &[KEY]
        )
        .is_err()
    );
    assert!(
        SourcePolicy::new(
            Distribution::Ubuntu,
            "https://example.org",
            "bookworm",
            &["main"],
            "amd64",
            "/key.gpg",
            &["1234"]
        )
        .is_err()
    );
}
