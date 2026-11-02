use dich_apt::{ControlError, DebianVersion, parse_control_stanzas, parse_dependencies};

const FIXTURE: &str = include_str!("fixtures/control/base-files.control");

#[test]
fn parses_real_control_fields_and_continuations() {
    let stanzas = parse_control_stanzas(FIXTURE.as_bytes()).unwrap();
    assert_eq!(stanzas.len(), 1);
    let stanza = &stanzas[0];
    assert_eq!(stanza.get("package"), Some("base-files"));
    assert_eq!(stanza.get("VERSION"), Some("13.8+deb13u1"));
    assert!(
        stanza
            .get("description")
            .unwrap()
            .contains("\nThis package contains")
    );
    assert_eq!(stanza.get("pre-depends"), Some("awk"));
}

#[test]
fn rejects_malformed_duplicate_and_overlarge_input() {
    for input in [
        " orphan\n",
        "Package a\n",
        "Package: a\npackage: b\n",
        "Package: a\nBad Field: x\n",
        "Package: a\n\u{0}\n",
    ] {
        assert!(
            parse_control_stanzas(input.as_bytes()).is_err(),
            "accepted {input:?}"
        );
    }
    assert!(matches!(
        parse_control_stanzas(&vec![b'x'; 256 * 1024 * 1024 + 1]),
        Err(ControlError::InputTooLarge)
    ));
    assert!(parse_control_stanzas(&[0xff]).is_err());
}

#[test]
fn separates_stanzas_and_preserves_folded_lines() {
    let input = b"Package: a\r\nDescription: short\r\n more\r\n .\r\n\r\nPackage: b\r\n";
    let stanzas = parse_control_stanzas(input).unwrap();
    assert_eq!(stanzas.len(), 2);
    assert_eq!(stanzas[0].get("description"), Some("short\nmore\n."));
    assert_eq!(stanzas[1].get("package"), Some("b"));
}

#[test]
fn parses_real_trixie_package_record_and_its_dependencies() {
    let input = include_bytes!("fixtures/control/trixie-0ad.Packages");
    let stanzas = parse_control_stanzas(input).unwrap();
    let stanza = &stanzas[0];
    assert_eq!(stanza.get("package"), Some("0ad"));
    assert!(DebianVersion::parse(stanza.get("version").unwrap()).is_ok());
    assert!(
        parse_dependencies(stanza.get("depends").unwrap())
            .unwrap()
            .len()
            > 20
    );
    assert_eq!(
        parse_dependencies(stanza.get("pre-depends").unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
#[ignore = "requires the cached Debian trixie main amd64 Packages index"]
fn parses_first_5000_records_of_real_debian_index() {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(
        "/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages",
    )
    .unwrap();
    let mut input = Vec::new();
    let mut count = 0;
    for line in BufReader::new(file).split(b'\n') {
        let line = line.unwrap();
        input.extend_from_slice(&line);
        input.push(b'\n');
        if line.is_empty() {
            count += 1;
            if count == 5000 {
                break;
            }
        }
    }
    let stanzas = parse_control_stanzas(&input).unwrap();
    assert_eq!(stanzas.len(), 5000);
    for stanza in stanzas {
        let name = stanza.get("package").unwrap();
        DebianVersion::parse(stanza.get("version").unwrap())
            .unwrap_or_else(|_| panic!("bad version for {name}"));
        for field in ["depends", "pre-depends"] {
            if let Some(value) = stanza.get(field) {
                parse_dependencies(value)
                    .unwrap_or_else(|_| panic!("bad {field} for {name}: {value}"));
            }
        }
    }
}
