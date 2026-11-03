//! Load a bounded candidate dataset from one authenticated, policy-matched cache snapshot.
use crate::{
    DebianUniverse, FreshnessPolicy, IndexLimits, SnapshotJournal, Source, check_release_policy,
    choose_index_format, parse_control_stanzas,
};
use dich_core::ArchitecturePolicy;
use std::{error::Error, fmt, time::SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniverseLoadError {
    Cache,
    Policy,
    Metadata,
    Limit,
}
impl fmt::Display for UniverseLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authenticated candidate load failed: {self:?}")
    }
}
impl Error for UniverseLoadError {}

/// Verified metadata dataset only. It is not a plan and does not authorize installation.
pub struct AuthenticatedUniverse {
    universe: DebianUniverse,
}
impl AuthenticatedUniverse {
    pub fn load(
        source: &Source,
        journal: &SnapshotJournal,
        freshness: FreshnessPolicy,
        policy: &ArchitecturePolicy,
    ) -> Result<Self, UniverseLoadError> {
        Self::load_with_clock(source, journal, freshness, policy, SystemTime::now)
    }
    pub(crate) fn load_with_clock(
        source: &Source,
        journal: &SnapshotJournal,
        freshness: FreshnessPolicy,
        policy: &ArchitecturePolicy,
        clock: impl Fn() -> SystemTime,
    ) -> Result<Self, UniverseLoadError> {
        let release = journal
            .load_release_with_clock(source, freshness, &clock)
            .map_err(|_| UniverseLoadError::Cache)?;
        check_release_policy(policy, &release).map_err(|_| UniverseLoadError::Policy)?;
        let mut stanzas = Vec::new();
        for component in source.components() {
            let format = choose_index_format(&release, component)
                .map_err(|_| UniverseLoadError::Metadata)?;
            let (index_release, index) = journal
                .load_index_with_clock(
                    source,
                    freshness,
                    component,
                    format,
                    IndexLimits::default(),
                    &clock,
                )
                .map_err(|_| UniverseLoadError::Cache)?;
            if index_release.release().contents() != release.release().contents() {
                return Err(UniverseLoadError::Cache);
            }
            let component_stanzas =
                parse_control_stanzas(index.contents()).map_err(|_| UniverseLoadError::Metadata)?;
            if stanzas.len().saturating_add(component_stanzas.len()) > 100_000 {
                return Err(UniverseLoadError::Limit);
            }
            stanzas.extend(component_stanzas);
        }
        let universe = DebianUniverse::from_stanzas(&stanzas, source.architecture())
            .map_err(|_| UniverseLoadError::Metadata)?;
        let current = journal
            .load_release_with_clock(source, freshness, &clock)
            .map_err(|_| UniverseLoadError::Cache)?;
        if !release.is_valid_at(clock())
            || current.release().contents() != release.release().contents()
        {
            return Err(UniverseLoadError::Cache);
        }
        Ok(Self { universe })
    }
    pub fn package_count(&self) -> usize {
        self.universe.len()
    }
}
