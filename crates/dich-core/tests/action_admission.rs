use dich_core::admission::{Action, Evidence, Rejection, assess_execution};

#[test]
fn unknown_or_incomplete_evidence_cannot_authorize_execution() {
    assert!(assess_execution(Evidence::Unexamined).contains(&Rejection::Unexamined));
    assert!(assess_execution(Evidence::Incomplete(&[])).contains(&Rejection::Incomplete));
    assert!(
        assess_execution(Evidence::Examined(&[])).contains(&Rejection::CompatibilityNotEstablished)
    );
}

#[test]
fn unsupported_dpkg_or_host_actions_always_fail_closed() {
    for action in [
        Action::DpkgState,
        Action::MaintainerScript,
        Action::Service,
        Action::KernelModule,
        Action::Trigger,
        Action::GlobalHostState,
        Action::Unknown,
    ] {
        let result = assess_execution(Evidence::Examined(&[action]));
        assert!(
            result.contains(&Rejection::UnsupportedAction(action)),
            "{action:?}"
        );
        assert!(result.contains(&Rejection::CompatibilityNotEstablished));
    }
}

#[test]
fn execution_is_denied_even_when_no_actions_are_reported() {
    assert!(dich_core::admission::admit_execution(Evidence::Examined(&[])).is_err());
}
