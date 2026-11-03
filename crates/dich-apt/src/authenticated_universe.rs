//! Load a bounded candidate dataset from one authenticated, policy-matched cache snapshot.
use crate::{
    DebianUniverse, FreshnessPolicy, IndexLimits, SnapshotJournal, Source, ValidatedRelease,
    check_release_policy, choose_index_format, parse_control_stanzas,
};
use dich_core::{
    ArchitecturePolicy,
    resolver::{ResolveError, SearchLimits, resolve},
};
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

#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    InvalidRequest,
    Cache,
    Limit,
    Unsupported(Vec<String>),
    Unsatisfiable(Vec<String>),
}
#[derive(Debug, PartialEq, Eq)]
pub struct MetadataPlan {
    pub packages: Vec<String>,
    pub trace: Vec<String>,
}

/// A metadata dataset; plans do not authorize fetching or installation.
pub struct AuthenticatedUniverse {
    universe: DebianUniverse,
    source: Source,
    freshness: FreshnessPolicy,
    release: ValidatedRelease,
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
        Ok(Self {
            universe,
            source: source.clone(),
            freshness,
            release,
        })
    }
    fn recheck(
        &self,
        journal: &SnapshotJournal,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<(), PlanError> {
        let release = journal
            .load_release_with_clock(&self.source, self.freshness, clock)
            .map_err(|_| PlanError::Cache)?;
        if !self.release.is_valid_at(clock())
            || release.release().contents() != self.release.release().contents()
        {
            return Err(PlanError::Cache);
        }
        for component in self.source.components() {
            let format =
                choose_index_format(&self.release, component).map_err(|_| PlanError::Cache)?;
            let (indexed, _) = journal
                .load_index_with_clock(
                    &self.source,
                    self.freshness,
                    component,
                    format,
                    IndexLimits::default(),
                    clock,
                )
                .map_err(|_| PlanError::Cache)?;
            if indexed.release().contents() != self.release.release().contents() {
                return Err(PlanError::Cache);
            }
        }
        Ok(())
    }
    /// Produce an informational metadata plan after rechecking the cache. It is not installable.
    pub fn plan(
        &self,
        journal: &SnapshotJournal,
        package: &str,
    ) -> Result<MetadataPlan, PlanError> {
        self.plan_with_clock(journal, package, SystemTime::now)
    }
    pub(crate) fn plan_with_clock(
        &self,
        journal: &SnapshotJournal,
        package: &str,
        clock: impl Fn() -> SystemTime,
    ) -> Result<MetadataPlan, PlanError> {
        self.recheck(journal, &clock)?;
        let request = self
            .universe
            .require(package)
            .map_err(|_| PlanError::InvalidRequest)?;
        let result = resolve(&self.universe, vec![request], SearchLimits::default());
        self.recheck(journal, &clock)?;
        let result = result.map_err(|error| match error {
            ResolveError::LimitExceeded => PlanError::Limit,
            ResolveError::Unsupported { trace } => PlanError::Unsupported(trace),
            ResolveError::Unsatisfiable { trace } => PlanError::Unsatisfiable(trace),
        })?;
        let packages = result
            .selected
            .into_iter()
            .map(|id| self.universe.label(id).ok_or(PlanError::Cache))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MetadataPlan {
            packages,
            trace: result.trace,
        })
    }
    pub fn package_count(&self) -> usize {
        self.universe.len()
    }
}
