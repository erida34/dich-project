#![forbid(unsafe_code)]
//! Package-level orchestration. Domain validation remains in apt, deb and store crates.

use dich_apt::{
    AuthenticatedUniverse, FetchRequest, FreshnessPolicy, HttpConnectProxy, MetadataPlan,
    PlanError, SnapshotJournal, Source, fetch_exact, fetch_exact_with_proxy,
};
use dich_core::{ArchitecturePolicy, Distribution, reference_graph::ReferenceGraph};
use dich_deb::{ArchiveReport, CompatibilityReport, CompatibilityStatus, Limits, inspect_deb};
use dich_store::{MetadataDb, ProfileGeneration, PublicationError, TreeOutcome};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_CLOSURE_PACKAGES: usize = 16;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub enum EngineError {
    Plan(PlanError),
    Fetch,
    ArtifactLimit,
    Inspection,
    UnsupportedClosure(Vec<String>),
    ProfileConflict,
    Store(PublicationError),
}
impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "package operation rejected: {self:?}")
    }
}
impl Error for EngineError {}

#[derive(Debug)]
pub struct InstalledObject {
    pub package: String,
    pub version: String,
    pub id: String,
    pub path: PathBuf,
    pub tree_outcome: TreeOutcome,
}

#[derive(Debug)]
pub struct InstallReport {
    pub plan: MetadataPlan,
    pub compatibility: CompatibilityReport,
    pub generation: ProfileGeneration,
    pub objects: Vec<InstalledObject>,
}

pub struct InstallRequest<'a> {
    pub package: &'a str,
    pub exact_version: Option<&'a str>,
    pub profile: &'a str,
    pub store_dir: &'a Path,
    pub proxy: Option<&'a HttpConnectProxy>,
}

pub fn plan_install(
    source: &Source,
    journal: &SnapshotJournal,
    freshness: FreshnessPolicy,
    package: &str,
    exact_version: Option<&str>,
) -> Result<MetadataPlan, EngineError> {
    let universe = load_universe(source, journal, freshness)?;
    let plan = match exact_version {
        Some(version) => universe.plan_exact(journal, package, version),
        None => universe.plan(journal, package),
    };
    plan.map_err(EngineError::Plan)
}

pub fn freshness_policy(
    max_age_seconds: u64,
    allow_missing_valid_until: bool,
) -> Result<FreshnessPolicy, EngineError> {
    FreshnessPolicy::new(
        std::time::Duration::from_secs(max_age_seconds),
        std::time::Duration::from_secs(300),
        !allow_missing_valid_until,
    )
    .map_err(|_| EngineError::Inspection)
}

/// Fetch, authenticate, inspect and select one complete DSO dependency closure in a profile.
/// It never executes package code or changes files outside the Dich store.
pub fn install_dso_profile(
    source: &Source,
    journal: &SnapshotJournal,
    freshness: FreshnessPolicy,
    request: InstallRequest<'_>,
) -> Result<InstallReport, EngineError> {
    let universe = load_universe(source, journal, freshness)?;
    let plan = match request.exact_version {
        Some(version) => universe.plan_exact(journal, request.package, version),
        None => universe.plan(journal, request.package),
    }
    .map_err(EngineError::Plan)?;
    if plan.pins.is_empty() || plan.pins.len() > MAX_CLOSURE_PACKAGES {
        return Err(EngineError::ArtifactLimit);
    }

    let mut fetched = Vec::with_capacity(plan.pins.len());
    let mut reports: Vec<ArchiveReport> = Vec::with_capacity(plan.pins.len());
    for pin in &plan.pins {
        let fetch_request = FetchRequest {
            component: &pin.component,
            name: &pin.name,
            version: &pin.version,
            max_bytes: MAX_ARTIFACT_BYTES,
        };
        let artifact = match request.proxy {
            Some(proxy) => fetch_exact_with_proxy(source, journal, freshness, fetch_request, proxy),
            None => fetch_exact(source, journal, freshness, fetch_request),
        }
        .map_err(|_| EngineError::Fetch)?;
        let mut stream = journal
            .load_artifact(artifact.authorization())
            .map_err(|_| EngineError::Fetch)?;
        let mut bytes = Vec::new();
        stream
            .by_ref()
            .take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| EngineError::Fetch)?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(EngineError::ArtifactLimit);
        }
        let report = inspect_deb(&bytes, Limits::default()).map_err(|_| EngineError::Inspection)?;
        reports.push(report);
        fetched.push(artifact);
    }

    let compatibility = if reports.len() == 1 {
        dich_deb::assess_compatibility(&reports[0])
    } else {
        dich_deb::assess_compatibility_closure(&reports)
    };
    if compatibility.status != CompatibilityStatus::Supported {
        return Err(EngineError::UnsupportedClosure(
            compatibility
                .evidence
                .iter()
                .map(|item| format!("{}: {}", item.code, item.detail))
                .collect(),
        ));
    }

    let mut store = MetadataDb::open(request.store_dir)
        .map_err(|_| EngineError::Store(PublicationError::Io))?;
    if let Some(current) = store
        .read_profile_generation(request.profile)
        .map_err(EngineError::Store)?
        && current.requested_package.as_deref() != Some(request.package)
    {
        return Err(EngineError::ProfileConflict);
    }
    let mut ids = Vec::with_capacity(fetched.len());
    let mut objects = Vec::with_capacity(fetched.len());
    for ((pin, artifact), report) in plan.pins.iter().zip(&fetched).zip(&reports) {
        let (identity, outcome) = store
            .stage_and_publish_cached_tree(journal, artifact.authorization())
            .map_err(EngineError::Store)?;
        let id = identity.hex();
        let elf_path = report
            .elf_objects
            .first()
            .ok_or(EngineError::Inspection)?
            .path
            .clone();
        ids.push(id.clone());
        objects.push(InstalledObject {
            package: pin.name.clone(),
            version: pin.version.clone(),
            id: id.clone(),
            path: request
                .store_dir
                .join("objects")
                .join(format!("{id}.tree"))
                .join(elf_path),
            tree_outcome: outcome,
        });
    }
    let ids_by_label: BTreeMap<_, _> = plan
        .packages
        .iter()
        .cloned()
        .zip(ids.iter().cloned())
        .collect();
    let root = ids_by_label
        .get(&plan.root)
        .ok_or(EngineError::Inspection)?;
    let dependency_edges: Vec<_> = plan
        .dependency_edges
        .iter()
        .map(|(from, to)| {
            Ok((
                ids_by_label
                    .get(from)
                    .ok_or(EngineError::Inspection)?
                    .clone(),
                ids_by_label.get(to).ok_or(EngineError::Inspection)?.clone(),
            ))
        })
        .collect::<Result<_, EngineError>>()?;
    let root_refs = [root.as_str()];
    let edge_refs: Vec<_> = dependency_edges
        .iter()
        .map(|(from, to)| (from.as_str(), to.as_str()))
        .collect();
    let graph = ReferenceGraph::new(&root_refs, &edge_refs).map_err(|_| EngineError::Inspection)?;
    let (graph_id, _) = store
        .put_reference_graph(&graph)
        .map_err(EngineError::Store)?;
    let (generation, _) = store
        .publish_package_profile_generation(request.profile, request.package, &graph_id)
        .map_err(EngineError::Store)?;
    Ok(InstallReport {
        plan,
        compatibility,
        generation,
        objects,
    })
}

fn load_universe(
    source: &Source,
    journal: &SnapshotJournal,
    freshness: FreshnessPolicy,
) -> Result<AuthenticatedUniverse, EngineError> {
    let distribution = match source.distribution() {
        dich_apt::Distribution::Debian => Distribution::Debian,
        dich_apt::Distribution::Ubuntu => Distribution::Ubuntu,
    };
    let policy = ArchitecturePolicy::new(distribution, source.suite(), source.architecture())
        .map_err(|_| EngineError::Inspection)?;
    AuthenticatedUniverse::load(source, journal, freshness, &policy).map_err(|_| EngineError::Fetch)
}
