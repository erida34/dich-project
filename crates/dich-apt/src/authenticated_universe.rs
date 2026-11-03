//! Load a bounded candidate dataset from one authenticated, policy-matched cache snapshot.
use crate::artifact::select_indexed_artifacts;
use crate::{
    DebianUniverse, FreshnessPolicy, IndexLimits, SnapshotJournal, Source, ValidatedRelease,
    check_release_policy, choose_index_format, parse_control_stanzas,
};
use dich_core::{
    ArchitecturePolicy,
    resolver::{ResolveError, SearchLimits, resolve},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::SystemTime,
};

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
pub struct MetadataPin {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub source_uri: String,
    pub distribution: String,
    pub suite: String,
    pub component: String,
    pub source_architecture: String,
    pub fingerprints: Vec<String>,
    pub release_sha256: String,
    pub artifact_sha256: String,
    pub filename: String,
    pub size: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub struct MetadataPlan {
    pub pins: Vec<MetadataPin>,
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
        let identities: BTreeSet<(String, String)> = result
            .selected
            .iter()
            .map(|id| self.universe.identity(*id).ok_or(PlanError::Cache))
            .collect::<Result<_, _>>()?;
        if identities.len() != result.selected.len() {
            return Err(PlanError::Cache);
        }
        let release_sha256 = hex(&Sha256::digest(self.release.release().contents()));
        let mut pins_by_identity = BTreeMap::new();
        for component in self.source.components() {
            let format =
                choose_index_format(&self.release, component).map_err(|_| PlanError::Cache)?;
            let (release, index) = journal
                .load_index_with_clock(
                    &self.source,
                    self.freshness,
                    component,
                    format,
                    IndexLimits::default(),
                    &clock,
                )
                .map_err(|_| PlanError::Cache)?;
            if release.release().contents() != self.release.release().contents() {
                return Err(PlanError::Cache);
            }
            for artifact in
                select_indexed_artifacts(&index, &identities).map_err(|_| PlanError::Cache)?
            {
                let key = (artifact.name().to_owned(), artifact.version().to_owned());
                let pin = MetadataPin {
                    name: key.0.clone(),
                    version: key.1.clone(),
                    architecture: artifact.architecture().into(),
                    source_uri: self.source.uri().into(),
                    distribution: match self.source.distribution() {
                        crate::Distribution::Debian => "debian",
                        crate::Distribution::Ubuntu => "ubuntu",
                    }
                    .into(),
                    suite: self.source.suite().into(),
                    component: component.into(),
                    source_architecture: self.source.architecture().into(),
                    fingerprints: self.source.fingerprints().to_vec(),
                    release_sha256: release_sha256.clone(),
                    artifact_sha256: hex(artifact.sha256()),
                    filename: artifact.path().into(),
                    size: artifact.size(),
                };
                if pins_by_identity.insert(key, pin).is_some() {
                    return Err(PlanError::Cache);
                }
            }
        }
        if pins_by_identity.len() != identities.len() {
            return Err(PlanError::Cache);
        }
        let pins = result
            .selected
            .iter()
            .map(|id| {
                let identity = self.universe.identity(*id).ok_or(PlanError::Cache)?;
                pins_by_identity.remove(&identity).ok_or(PlanError::Cache)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.recheck(journal, &clock)?;
        let packages = result
            .selected
            .into_iter()
            .map(|id| self.universe.label(id).ok_or(PlanError::Cache))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MetadataPlan {
            pins,
            packages,
            trace: result.trace,
        })
    }
    pub fn package_count(&self) -> usize {
        self.universe.len()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
