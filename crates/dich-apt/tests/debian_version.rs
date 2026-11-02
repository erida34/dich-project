use dich_apt::DebianVersion;
use std::cmp::Ordering;

#[test]
fn debian_version_ordering_fixtures() {
    let ordered = [
        ("1.0~rc1", "1.0"),
        ("1.0", "1.0-1"),
        ("1.0-1", "1.0-1+b1"),
        ("1.0-1+b1", "1.0-2"),
        ("1.0-2", "1.0.1-1"),
        ("1.0.1-1", "1:0.1-1"),
        ("1:0.1-1", "2:0-1"),
        ("1.0a", "1.0+"),
        ("1.0~~", "1.0~"),
        ("1.0-1~bpo12+1", "1.0-1"),
        ("1.0-1ubuntu1", "1.0-1ubuntu2"),
        ("1.0-9", "1.0-10"),
    ];
    for (left, right) in ordered {
        let left = DebianVersion::parse(left).unwrap();
        let right = DebianVersion::parse(right).unwrap();
        assert_eq!(left.cmp(&right), Ordering::Less, "{left:?} vs {right:?}");
        assert_eq!(right.cmp(&left), Ordering::Greater);
    }
    for (left, right) in [("1.0", "1.0-0"), ("01:1.000", "1:1.0"), ("1.0-01", "1.0-1")] {
        assert_eq!(
            DebianVersion::parse(left).unwrap(),
            DebianVersion::parse(right).unwrap()
        );
    }
}

#[test]
fn rejects_invalid_versions_without_integer_overflow() {
    for bad in [
        "", "-1", "abc", "1.0-", "x:1.0", ":1", "1:foo", "1.0_1", "1.0-1:2", "1.0\n",
    ] {
        assert!(DebianVersion::parse(bad).is_err(), "accepted {bad:?}");
    }
    assert!(DebianVersion::parse(&"9".repeat(4097)).is_err());
    let a = DebianVersion::parse("999999999999999999999999999:1").unwrap();
    let b = DebianVersion::parse("1000000000000000000000000000:1").unwrap();
    assert!(a < b);
}

#[test]
#[ignore = "requires Debian dpkg as read-only version comparison oracle"]
fn ordering_matches_dpkg() {
    use std::process::{Command, Stdio};
    let versions = [
        "0",
        "1",
        "1.0",
        "1.00",
        "1.0-0",
        "1.0-1",
        "1.0-1+b1",
        "1.0-1~bpo12+1",
        "1.0~rc1",
        "1.0~~",
        "1.0a",
        "1.0+",
        "1.0.1-1",
        "1:0.1-1",
        "2:0-1",
        "1.0-9",
        "1.0-10",
        "1.0-1ubuntu1",
        "1.0-1ubuntu2",
        "1.0+really2.0-3",
    ];
    for a in versions {
        for b in versions {
            let compare = |operator| {
                Command::new("/usr/bin/dpkg")
                    .args(["--compare-versions", a, operator, b])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            };
            let expected = if compare("lt") {
                Ordering::Less
            } else if compare("eq") {
                Ordering::Equal
            } else {
                Ordering::Greater
            };
            assert_eq!(
                DebianVersion::parse(a)
                    .unwrap()
                    .cmp(&DebianVersion::parse(b).unwrap()),
                expected,
                "{a} vs {b}"
            );
        }
    }
}
