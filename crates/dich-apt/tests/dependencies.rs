use dich_apt::{Comparison, parse_dependencies};

#[test]
fn parses_real_relations_with_alternatives_and_versions() {
    let groups = parse_dependencies(
        "libc6 (>= 2.34), libssl3t64 | libssl3 (>= 3.0), zlib1g:any (<< 1:2.0-1)",
    )
    .unwrap();
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[1].alternatives().len(), 2);
    let relation = &groups[2].alternatives()[0];
    assert_eq!(relation.name(), "zlib1g");
    assert_eq!(relation.qualifier(), Some("any"));
    let constraint = relation.version().unwrap();
    assert_eq!(constraint.operator(), Comparison::Less);
    assert_eq!(constraint.version().as_str(), "1:2.0-1");
}

#[test]
fn retains_architecture_restrictions_and_build_profiles() {
    let groups = parse_dependencies(
        "pkg:native (>= 1.2-3) [amd64 !arm64] <stage1 !nocheck> <!cross> | fallback:amd64",
    )
    .unwrap();
    let relation = &groups[0].alternatives()[0];
    assert_eq!(relation.architectures(), &["amd64", "!arm64"]);
    assert_eq!(
        relation.profiles(),
        &[vec!["stage1", "!nocheck"], vec!["!cross"]]
    );
    assert_eq!(groups[0].alternatives()[1].qualifier(), Some("amd64"));
}

#[test]
fn rejects_malformed_or_unsupported_relation_syntax() {
    for value in [
        "",
        "a | | b",
        "a,",
        "a (>=)",
        "a (> 1)",
        "a (>= nonsense)",
        "a [",
        "a []",
        "a <>",
        "a (>= 1) (<< 2)",
        "a:Bad",
        "a;evil",
        "a [amd64] garbage",
    ] {
        assert!(parse_dependencies(value).is_err(), "accepted {value:?}");
    }
}
