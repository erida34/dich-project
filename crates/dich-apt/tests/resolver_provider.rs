use dich_apt::{DebianUniverse, parse_control_stanzas};
use dich_core::resolver::{SearchLimits, resolve};

#[test]
fn chooses_highest_satisfying_version_and_backtracks_on_conflicts() {
    let fixture = b"Package: root\nVersion: 1\nArchitecture: amd64\nDepends: lib (>= 1), extra\n\nPackage: lib\nVersion: 2\nArchitecture: amd64\nConflicts: extra\n\nPackage: lib\nVersion: 1\nArchitecture: amd64\n\nPackage: extra\nVersion: 1\nArchitecture: all\n";
    let stanzas = parse_control_stanzas(fixture).unwrap();
    let universe = DebianUniverse::from_stanzas(&stanzas, "amd64").unwrap();
    let root = universe.require("root").unwrap();
    let plan = resolve(&universe, vec![root], SearchLimits::default()).unwrap();
    let selected = plan
        .selected
        .iter()
        .map(|id| universe.label(*id).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(selected, vec!["root=1", "lib=1", "extra=1"]);
}

#[test]
fn provides_must_satisfy_the_declared_version_and_package_conflicts() {
    let fixture = b"Package: root\nVersion: 1\nArchitecture: amd64\nDepends: virtual (>= 2)\n\nPackage: a-provider\nVersion: 99\nArchitecture: amd64\nProvides: virtual (= 1)\n\nPackage: z-provider\nVersion: 1\nArchitecture: amd64\nProvides: virtual (= 2)\n";
    let universe =
        DebianUniverse::from_stanzas(&parse_control_stanzas(fixture).unwrap(), "amd64").unwrap();
    let plan = resolve(
        &universe,
        vec![universe.require("root").unwrap()],
        SearchLimits::default(),
    )
    .unwrap();
    assert_eq!(
        plan.selected
            .iter()
            .map(|id| universe.label(*id).unwrap())
            .collect::<Vec<_>>(),
        vec!["root=1", "z-provider=1"]
    );
}

#[test]
fn unsupported_semantics_and_system_packages_are_never_silently_selected() {
    for field in [
        "Pre-Depends: libc6",
        "Depends: lib:any",
        "Depends: lib [amd64]",
        "Essential: yes",
        "Priority: required",
    ] {
        let input = format!("Package: root\nVersion: 1\nArchitecture: amd64\n{field}\n");
        let universe = DebianUniverse::from_stanzas(
            &parse_control_stanzas(input.as_bytes()).unwrap(),
            "amd64",
        )
        .unwrap();
        assert!(
            resolve(
                &universe,
                vec![universe.require("root").unwrap()],
                SearchLimits::default()
            )
            .is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn invalid_candidate_ids_fail_closed_without_panicking() {
    use dich_core::resolver::Provider;
    let universe = DebianUniverse::from_stanzas(&[], "amd64").unwrap();
    assert!(universe.label(999).is_none());
    assert!(universe.incompatible(&999, &0));
    let requirements = universe.requirements(&999);
    assert!(resolve(&universe, requirements, SearchLimits::default()).is_err());
}

#[test]
fn excessive_candidate_alternatives_stop_with_limit_instead_of_partial_plan() {
    use dich_core::resolver::ResolveError;
    let mut fixture = String::new();
    for i in 0..1025 {
        fixture.push_str(&format!(
            "Package: provider-{i}\nVersion: 1\nArchitecture: amd64\nProvides: virtual\n\n"
        ));
    }
    let universe =
        DebianUniverse::from_stanzas(&parse_control_stanzas(fixture.as_bytes()).unwrap(), "amd64")
            .unwrap();
    assert!(matches!(
        resolve(
            &universe,
            vec![universe.require("virtual").unwrap()],
            SearchLimits::default()
        ),
        Err(ResolveError::LimitExceeded)
    ));
}

#[test]
fn unsupported_candidate_is_not_reported_as_proven_unsatisfiable() {
    use dich_core::resolver::ResolveError;
    let stanzas = parse_control_stanzas(
        b"Package: root\nVersion: 1\nArchitecture: amd64\nPre-Depends: libc6\n",
    )
    .unwrap();
    let universe = DebianUniverse::from_stanzas(&stanzas, "amd64").unwrap();
    assert!(matches!(
        resolve(
            &universe,
            vec![universe.require("root").unwrap()],
            SearchLimits::default()
        ),
        Err(ResolveError::Unsupported { .. })
    ));
}

#[test]
fn duplicate_package_identity_is_not_picked_by_fixture_order() {
    let stanzas = parse_control_stanzas(b"Package: duplicate\nVersion: 1\nArchitecture: amd64\n\nPackage: duplicate\nVersion: 1\nArchitecture: amd64\nDepends: other\n").unwrap();
    assert!(DebianUniverse::from_stanzas(&stanzas, "amd64").is_err());
}

#[test]
fn unqualified_dependencies_allow_native_packages_with_multiarch_flags() {
    for flag in ["same", "foreign", "allowed"] {
        let fixture = format!(
            "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: library\n\nPackage: library\nVersion: 1\nArchitecture: amd64\nMulti-Arch: {flag}\n"
        );
        let universe = DebianUniverse::from_stanzas(
            &parse_control_stanzas(fixture.as_bytes()).unwrap(),
            "amd64",
        )
        .unwrap();
        let plan = resolve(
            &universe,
            vec![universe.require("root").unwrap()],
            SearchLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.selected.len(), 2);
    }
}

#[test]
fn architecture_all_with_multiarch_same_is_conservatively_unsupported() {
    let fixture = b"Package: root\nVersion: 1\nArchitecture: all\nMulti-Arch: same\n";
    let universe =
        DebianUniverse::from_stanzas(&parse_control_stanzas(fixture).unwrap(), "amd64").unwrap();
    assert!(matches!(
        resolve(
            &universe,
            vec![universe.require("root").unwrap()],
            SearchLimits::default()
        ),
        Err(dich_core::resolver::ResolveError::Unsupported { .. })
    ));
}
