#![forbid(unsafe_code)]
//! Core policy models; package resolution and installation are not implemented.
use std::{error::Error, fmt};

pub mod admission;
pub mod resolver;

/// The distribution must be selected explicitly by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distribution {
    Debian,
    Ubuntu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    InvalidRelease,
    InvalidArchitecture,
    DistributionMismatch,
    ReleaseMismatch,
    ArchitectureMismatch,
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "release/architecture policy rejected input: {self:?}")
    }
}
impl Error for PolicyError {}

/// Exact source boundary for a future resolver. It does not authenticate sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchitecturePolicy {
    distribution: Distribution,
    suite: String,
    architecture: String,
}
impl ArchitecturePolicy {
    pub fn new(
        distribution: Distribution,
        suite: &str,
        architecture: &str,
    ) -> Result<Self, PolicyError> {
        let valid = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !s.starts_with('-')
                && !s.ends_with('-')
                && !s.contains("--")
        };
        let alias = [
            "stable",
            "oldstable",
            "oldoldstable",
            "testing",
            "unstable",
            "sid",
            "experimental",
            "devel",
            "rolling",
        ];
        if !valid(suite)
            || alias
                .iter()
                .any(|a| suite == *a || suite.starts_with(&format!("{a}-")))
        {
            return Err(PolicyError::InvalidRelease);
        }
        if !valid(architecture)
            || matches!(architecture, "all" | "any")
            || architecture.starts_with("any-")
            || architecture.ends_with("-any")
        {
            return Err(PolicyError::InvalidArchitecture);
        }
        Ok(Self {
            distribution,
            suite: suite.into(),
            architecture: architecture.into(),
        })
    }
    pub fn check_source(
        &self,
        distribution: Distribution,
        suite: &str,
        architecture: &str,
    ) -> Result<(), PolicyError> {
        if self.distribution != distribution {
            return Err(PolicyError::DistributionMismatch);
        }
        if self.suite != suite {
            return Err(PolicyError::ReleaseMismatch);
        }
        if self.architecture != architecture {
            return Err(PolicyError::ArchitectureMismatch);
        }
        Ok(())
    }
    pub fn check_package_architecture(&self, architecture: &str) -> Result<(), PolicyError> {
        if architecture == self.architecture || architecture == "all" {
            Ok(())
        } else {
            Err(PolicyError::ArchitectureMismatch)
        }
    }
}
