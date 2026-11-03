//! Bounded generic search engine; providers must enforce package semantics and trust.
use std::fmt::Debug;

#[derive(Debug)]
pub enum ValidationError {
    Unsupported(String),
    Limit,
}

pub trait Provider {
    type Candidate: Clone + Eq + Debug;
    type Requirement: Clone + Debug;
    /// Candidates must be returned in deterministic preference order.
    fn candidates(&self, requirement: &Self::Requirement) -> Vec<Self::Candidate>;
    /// True if matching candidates were excluded because their semantics are unsupported.
    fn has_unsupported(&self, _requirement: &Self::Requirement) -> bool {
        false
    }
    fn requirements(&self, candidate: &Self::Candidate) -> Vec<Self::Requirement>;
    fn incompatible(&self, left: &Self::Candidate, right: &Self::Candidate) -> bool;
    /// Reject a completed selection if the provider cannot safely interpret it.
    fn validate_solution(&self, _selected: &[Self::Candidate]) -> Result<(), ValidationError> {
        Ok(())
    }
    fn describe_candidate(&self, candidate: &Self::Candidate) -> String {
        format!("{candidate:?}")
    }
    fn describe_requirement(&self, requirement: &Self::Requirement) -> String {
        format!("{requirement:?}")
    }
}
#[derive(Debug, Clone, Copy)]
pub struct SearchLimits {
    pub max_steps: usize,
    pub max_selected: usize,
}
impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_steps: 20_000,
            max_selected: 128,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    LimitExceeded,
    Unsatisfiable { trace: Vec<String> },
    Unsupported { trace: Vec<String> },
}
#[derive(Debug)]
pub struct Resolution<C> {
    pub selected: Vec<C>,
    pub trace: Vec<String>,
}

/// Search only; this is not a package plan and does not authenticate provider data.
pub fn resolve<P: Provider>(
    provider: &P,
    requirements: Vec<P::Requirement>,
    limits: SearchLimits,
) -> Result<Resolution<P::Candidate>, ResolveError> {
    if limits.max_steps == 0
        || limits.max_steps > 100_000
        || limits.max_selected == 0
        || limits.max_selected > 128
        || requirements.len() > 256
    {
        return Err(ResolveError::LimitExceeded);
    }
    let mut search = Search {
        provider,
        limits,
        steps: 0,
        unsupported_seen: false,
        trace: Vec::new(),
    };
    let selected = search.visit(requirements, Vec::new(), 0)?;
    match selected {
        Some(selected) => Ok(Resolution {
            selected,
            trace: search.trace,
        }),
        None if search.unsupported_seen => Err(ResolveError::Unsupported {
            trace: search.trace,
        }),
        None => Err(ResolveError::Unsatisfiable {
            trace: search.trace,
        }),
    }
}
struct Search<'a, P: Provider> {
    provider: &'a P,
    limits: SearchLimits,
    steps: usize,
    unsupported_seen: bool,
    trace: Vec<String>,
}
impl<P: Provider> Search<'_, P> {
    fn note(&mut self, note: String) {
        if self.trace.len() < 256 {
            self.trace.push(note);
        }
    }
    fn visit(
        &mut self,
        mut pending: Vec<P::Requirement>,
        selected: Vec<P::Candidate>,
        depth: usize,
    ) -> Result<Option<Vec<P::Candidate>>, ResolveError> {
        self.steps += 1;
        if self.steps > self.limits.max_steps || depth > 256 || pending.len() > 256 {
            return Err(ResolveError::LimitExceeded);
        }
        if pending.is_empty() {
            match self.provider.validate_solution(&selected) {
                Ok(()) => (),
                Err(ValidationError::Limit) => return Err(ResolveError::LimitExceeded),
                Err(ValidationError::Unsupported(reason)) => {
                    self.unsupported_seen = true;
                    self.note(reason);
                    return Ok(None);
                }
            }
            return Ok(Some(selected));
        }
        let requirement = pending.remove(0);
        self.unsupported_seen |= self.provider.has_unsupported(&requirement);
        let options = self.provider.candidates(&requirement);
        if options.len() > 1024 {
            return Err(ResolveError::LimitExceeded);
        }
        if let Some(candidate) = options
            .iter()
            .find(|candidate| selected.contains(candidate))
        {
            self.note(format!(
                "{} satisfied by already selected {}",
                self.provider.describe_requirement(&requirement),
                self.provider.describe_candidate(candidate)
            ));
            return self.visit(pending, selected, depth + 1);
        }
        if options.is_empty() {
            self.note(format!(
                "no candidate for {}",
                self.provider.describe_requirement(&requirement)
            ));
        }
        for candidate in options {
            if let Some(old) = selected.iter().find(|old| {
                self.provider.incompatible(old, &candidate)
                    || self.provider.incompatible(&candidate, old)
            }) {
                self.note(format!(
                    "conflict between {} and {}",
                    self.provider.describe_candidate(&candidate),
                    self.provider.describe_candidate(old)
                ));
                continue;
            }
            if selected.len() >= self.limits.max_selected {
                return Err(ResolveError::LimitExceeded);
            }
            self.note(format!(
                "considering {}",
                self.provider.describe_candidate(&candidate)
            ));
            let mut next = selected.clone();
            next.push(candidate.clone());
            let mut obligations = self.provider.requirements(&candidate);
            if obligations.len().saturating_add(pending.len()) > 256 {
                return Err(ResolveError::LimitExceeded);
            }
            obligations.extend(pending.iter().cloned());
            if let Some(result) = self.visit(obligations, next, depth + 1)? {
                return Ok(Some(result));
            }
            self.note(format!(
                "backtrack from {}",
                self.provider.describe_candidate(&candidate)
            ));
        }
        Ok(None)
    }
}
