//! Bridge an authenticated Release source to the resolver's explicit boundary.
use crate::{Distribution, ValidatedRelease};
use dich_core::{ArchitecturePolicy, PolicyError};

/// Check source identity only. Callers must separately recheck freshness at use time.
pub fn check_release_policy(
    policy: &ArchitecturePolicy,
    release: &ValidatedRelease,
) -> Result<(), PolicyError> {
    let source = release.source();
    let distribution = match source.distribution() {
        Distribution::Debian => dich_core::Distribution::Debian,
        Distribution::Ubuntu => dich_core::Distribution::Ubuntu,
    };
    policy.check_source(distribution, source.suite(), source.architecture())
}
