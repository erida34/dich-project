//! Fail-closed admission policy; evidence cannot currently authorize execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    DpkgState,
    MaintainerScript,
    Service,
    KernelModule,
    Trigger,
    GlobalHostState,
    Unknown,
}
#[derive(Debug, Clone, Copy)]
pub enum Evidence<'a> {
    Unexamined,
    Incomplete(&'a [Action]),
    Examined(&'a [Action]),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Unexamined,
    Incomplete,
    UnsupportedAction(Action),
    CompatibilityNotEstablished,
}

/// Returns rejection reasons, never execution permission. No analyzer currently produces trusted evidence.
pub fn assess_execution(evidence: Evidence<'_>) -> Vec<Rejection> {
    let mut reasons = Vec::new();
    let actions = match evidence {
        Evidence::Unexamined => {
            reasons.push(Rejection::Unexamined);
            &[][..]
        }
        Evidence::Incomplete(actions) => {
            reasons.push(Rejection::Incomplete);
            actions
        }
        Evidence::Examined(actions) => actions,
    };
    for action in actions {
        let reason = Rejection::UnsupportedAction(*action);
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    reasons.push(Rejection::CompatibilityNotEstablished);
    reasons
}

/// Fail closed until trusted archive and compatibility evidence can be produced and reviewed.
pub fn admit_execution(evidence: Evidence<'_>) -> Result<(), Vec<Rejection>> {
    Err(assess_execution(evidence))
}
