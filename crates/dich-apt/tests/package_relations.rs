use dich_apt::{MultiArch, PackageRelations, SystemBoundary, parse_control_stanzas};

#[test]
fn models_relationships_and_system_boundary_from_binary_package_fixture() {
    let input = b"Package: example\nVersion: 1.0-1\nArchitecture: amd64\nDepends: liba (>= 1:2.0-1) | libb:any\nPre-Depends: base:native\nConflicts: old (<< 2)\nBreaks: incompatible (<< 3)\nProvides: virtual-name (= 1.0)\nMulti-Arch: foreign\nEssential: yes\nPriority: required\n";
    let stanzas = parse_control_stanzas(input).unwrap();
    let model = PackageRelations::from_stanza(&stanzas[0]).unwrap();
    assert_eq!(model.depends()[0].alternatives().len(), 2);
    assert_eq!(
        model.depends()[0].alternatives()[1].qualifier(),
        Some("any")
    );
    assert_eq!(
        model.pre_depends()[0].alternatives()[0].qualifier(),
        Some("native")
    );
    assert_eq!(model.conflicts()[0].alternatives()[0].name(), "old");
    assert_eq!(model.breaks()[0].alternatives()[0].name(), "incompatible");
    assert!(model.essential());
    assert!(model.required_priority());
    assert_eq!(
        model.provides()[0].alternatives()[0]
            .version()
            .unwrap()
            .version()
            .as_str(),
        "1.0"
    );
    assert_eq!(model.multi_arch(), MultiArch::Foreign);
    assert_eq!(model.system_boundary(), SystemBoundary::Essential);
}

#[test]
fn rejects_ambiguous_relationships_and_invalid_system_flags() {
    for field in [
        "Essential: maybe",
        "Multi-Arch: unknown",
        "Provides: a | b",
        "Provides: x (>= 2)",
        "Conflicts: a | b",
        "Breaks: a | b",
        "Depends: a,",
        "Priority: garbage",
    ] {
        let input = format!("Package: example\nVersion: 1\nArchitecture: amd64\n{field}\n");
        let stanzas = parse_control_stanzas(input.as_bytes()).unwrap();
        assert!(
            PackageRelations::from_stanza(&stanzas[0]).is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn required_priority_is_not_conflated_with_essential() {
    for (priority, expected) in [
        ("required", SystemBoundary::Required),
        ("important", SystemBoundary::Ordinary),
        ("optional", SystemBoundary::Ordinary),
    ] {
        let input = format!("Priority: {priority}\n");
        let stanzas = parse_control_stanzas(input.as_bytes()).unwrap();
        assert_eq!(
            PackageRelations::from_stanza(&stanzas[0])
                .unwrap()
                .system_boundary(),
            expected
        );
    }
}

#[test]
#[ignore = "requires the cached Debian trixie main amd64 Packages index"]
fn models_first_5000_real_debian_package_relationships() {
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
    for stanza in &stanzas {
        PackageRelations::from_stanza(stanza)
            .unwrap_or_else(|e| panic!("{}: {e}", stanza.get("package").unwrap_or("missing name")));
    }
}
