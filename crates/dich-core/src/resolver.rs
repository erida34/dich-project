//! Bounded generic search engine; providers must enforce package semantics and trust.
use std::fmt::Debug;

pub trait Provider {
    type Candidate: Clone + Eq + Debug;
    type Requirement: Clone + Debug;
    /// Candidates must be returned in deterministic preference order.
    fn candidates(&self, requirement: &Self::Requirement) -> Vec<Self::Candidate>;
    fn requirements(&self, candidate: &Self::Candidate) -> Vec<Self::Requirement>;
    fn incompatible(&self, left: &Self::Candidate, right: &Self::Candidate) -> bool;
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
        trace: Vec::new(),
    };
    let selected = search.visit(requirements, Vec::new(), 0)?;
    match selected {
        Some(selected) => Ok(Resolution {
            selected,
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
            return Ok(Some(selected));
        }
        let requirement = pending.remove(0);
        let options = self.provider.candidates(&requirement);
        if options.len() > 1024 {
            return Err(ResolveError::LimitExceeded);
        }
        if options.iter().any(|candidate| selected.contains(candidate)) {
            return self.visit(pending, selected, depth + 1);
        }
        if options.is_empty() {
            self.note(format!("no candidate for {requirement:?}"));
        }
        for candidate in options {
            if selected.iter().any(|old| {
                self.provider.incompatible(old, &candidate)
                    || self.provider.incompatible(&candidate, old)
            }) {
                self.note(format!("conflict for {candidate:?}"));
                continue;
            }
            if selected.len() >= self.limits.max_selected {
                return Err(ResolveError::LimitExceeded);
            }
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
            self.note(format!("backtrack from {candidate:?}"));
        }
        Ok(None)
    }
}
