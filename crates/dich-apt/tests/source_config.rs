use dich_apt::{Distribution, import_sources, parse_source_config, read_source_config};

const POLICY: &str = include_str!("fixtures/source-policy.toml");
const SOURCE: &str = include_str!("fixtures/debian.sources");

#[test]
fn config_file_supplies_policy_for_deb822_import() {
    let config = parse_source_config(POLICY).unwrap();
    assert_eq!(config.len(), 1);
    assert_eq!(config[0].sources_file(), "/etc/dich/sources/debian.sources");
    let sources = import_sources(SOURCE, config[0].policy()).unwrap();
    assert_eq!(sources[0].distribution(), Distribution::Debian);
}

#[test]
fn config_rejects_ambiguous_missing_and_insecure_policy() {
    let cases = [
        POLICY.replace("distribution = \"debian\"", "distribution = \"other\""),
        POLICY.replace("distribution = \"debian\"", ""),
        POLICY.replace("/etc/dich/sources/debian.sources", "../sources"),
        POLICY.replace(
            "fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]",
            "fingerprints = []",
        ),
        format!("{POLICY}\ntrusted = true\n"),
        format!("{POLICY}\n{POLICY}"),
        "sources = []".to_string(),
        "x".repeat(1_048_577),
    ];
    for input in cases {
        assert!(
            parse_source_config(&input).is_err(),
            "accepted policy {input:.100}"
        );
    }
}

#[test]
fn reads_bounded_utf8_configuration_from_a_reader() {
    assert_eq!(read_source_config(POLICY.as_bytes()).unwrap().len(), 1);
    assert!(read_source_config(&b"\xff"[..]).is_err());
    assert!(read_source_config(std::io::repeat(b'x')).is_err());
    struct Broken;
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("failure"))
        }
    }
    assert!(read_source_config(Broken).is_err());
}
