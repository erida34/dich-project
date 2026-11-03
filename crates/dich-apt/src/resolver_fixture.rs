//! Experimental fixture provider; not connected to authenticated sources or CLI plans.
use crate::{
    Comparison, ControlStanza, DebianVersion, DependencyGroup, DependencyRelation, MultiArch,
    PackageRelations, SystemBoundary, parse_dependencies,
};
use dich_core::resolver::Provider;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniverseError;
#[derive(Debug, Clone)]
pub struct Requirement(Vec<DependencyRelation>);
#[derive(Debug)]
struct Candidate {
    name: String,
    version: DebianVersion,
    relations: PackageRelations,
    supported: bool,
}
#[derive(Debug)]
pub struct DebianUniverse {
    candidates: Vec<Candidate>,
    names: BTreeMap<String, Vec<usize>>,
}
impl DebianUniverse {
    /// Parses untrusted stanzas for fixture evaluation. Does not authenticate or authorize anything.
    pub fn from_stanzas(
        stanzas: &[ControlStanza],
        architecture: &str,
    ) -> Result<Self, UniverseError> {
        if stanzas.len() > 100_000 || architecture.is_empty() {
            return Err(UniverseError);
        }
        let mut candidates = Vec::with_capacity(stanzas.len());
        let mut identities = BTreeSet::new();
        for stanza in stanzas {
            let name = stanza.get("package").ok_or(UniverseError)?;
            let parsed = parse_dependencies(name).map_err(|_| UniverseError)?;
            if parsed.len() != 1
                || parsed[0].alternatives().len() != 1
                || parsed[0].alternatives()[0].name() != name
            {
                return Err(UniverseError);
            }
            let version = DebianVersion::parse(stanza.get("version").ok_or(UniverseError)?)
                .map_err(|_| UniverseError)?;
            if !identities.insert((name.to_owned(), version.as_str().to_owned())) {
                return Err(UniverseError);
            }
            let arch = stanza.get("architecture").ok_or(UniverseError)?;
            let relations = PackageRelations::from_stanza(stanza).map_err(|_| UniverseError)?;
            let simple = |groups: &[DependencyGroup]| {
                groups.iter().flat_map(|g| g.alternatives()).all(|r| {
                    r.qualifier().is_none()
                        && r.architectures().is_empty()
                        && r.profiles().is_empty()
                })
            };
            let supported = (arch == architecture || arch == "all")
                && relations.pre_depends().is_empty()
                && relations.system_boundary() == SystemBoundary::Ordinary
                && relations.multi_arch() == MultiArch::No
                && simple(relations.depends())
                && simple(relations.conflicts())
                && simple(relations.breaks())
                && simple(relations.provides());
            candidates.push(Candidate {
                name: name.into(),
                version,
                relations,
                supported,
            });
        }
        let mut names: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut entries = 0usize;
        for (id, candidate) in candidates.iter().enumerate() {
            let mut keys = BTreeSet::new();
            keys.insert(candidate.name.as_str());
            for relation in candidate
                .relations
                .provides()
                .iter()
                .flat_map(|group| group.alternatives())
            {
                keys.insert(relation.name());
            }
            entries = entries.checked_add(keys.len()).ok_or(UniverseError)?;
            if entries > 250_000 {
                return Err(UniverseError);
            }
            for key in keys {
                names.entry(key.to_owned()).or_default().push(id);
            }
        }
        Ok(Self { candidates, names })
    }
    pub fn len(&self) -> usize {
        self.candidates.len()
    }
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
    pub fn require(&self, name: &str) -> Result<Requirement, UniverseError> {
        let parsed = parse_dependencies(name).map_err(|_| UniverseError)?;
        if parsed.len() != 1
            || parsed[0].alternatives().len() != 1
            || parsed[0].alternatives()[0].name() != name
        {
            return Err(UniverseError);
        }
        Ok(Requirement(parsed[0].alternatives().to_vec()))
    }
    pub fn label(&self, id: usize) -> Option<String> {
        let c = self.candidates.get(id)?;
        Some(format!("{}={}", c.name, c.version.as_str()))
    }
}
fn compare(version: &DebianVersion, relation: &DependencyRelation) -> bool {
    relation
        .version()
        .is_none_or(|constraint| match constraint.operator() {
            Comparison::Less => version < constraint.version(),
            Comparison::LessOrEqual => version <= constraint.version(),
            Comparison::Equal => version == constraint.version(),
            Comparison::GreaterOrEqual => version >= constraint.version(),
            Comparison::Greater => version > constraint.version(),
        })
}
fn matches(candidate: &Candidate, relation: &DependencyRelation) -> bool {
    if candidate.name == relation.name() && compare(&candidate.version, relation) {
        return true;
    }
    candidate
        .relations
        .provides()
        .iter()
        .flat_map(|g| g.alternatives())
        .any(|provided| {
            if provided.name() != relation.name() {
                return false;
            }
            match (provided.version(), relation.version()) {
                (_, None) => true,
                (Some(version), Some(_)) => compare(version.version(), relation),
                (None, Some(_)) => false,
            }
        })
}
impl Provider for DebianUniverse {
    type Candidate = usize;
    type Requirement = Requirement;
    fn candidates(&self, requirement: &Requirement) -> Vec<usize> {
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        for relation in &requirement.0 {
            let mut choices = Vec::new();
            for id in self.names.get(relation.name()).into_iter().flatten() {
                let candidate = &self.candidates[*id];
                if candidate.supported && matches(candidate, relation) && !seen.contains(id) {
                    choices.push(*id);
                    if choices.len() + result.len() > 1024 {
                        result.extend(choices);
                        return result;
                    }
                }
            }
            choices.sort_by(|a, b| {
                self.candidates[*b]
                    .version
                    .cmp(&self.candidates[*a].version)
                    .then_with(|| self.candidates[*a].name.cmp(&self.candidates[*b].name))
                    .then_with(|| a.cmp(b))
            });
            for id in choices {
                if seen.insert(id) {
                    result.push(id);
                }
            }
        }
        result
    }
    fn has_unsupported(&self, requirement: &Requirement) -> bool {
        requirement.0.iter().any(|relation| {
            self.names
                .get(relation.name())
                .into_iter()
                .flatten()
                .any(|id| {
                    let candidate = &self.candidates[*id];
                    !candidate.supported && matches(candidate, relation)
                })
        })
    }
    fn requirements(&self, candidate: &usize) -> Vec<Requirement> {
        let Some(candidate) = self.candidates.get(*candidate) else {
            return vec![Requirement(Vec::new())];
        };
        candidate
            .relations
            .depends()
            .iter()
            .map(|group| Requirement(group.alternatives().to_vec()))
            .collect()
    }
    fn incompatible(&self, left: &usize, right: &usize) -> bool {
        let (Some(a), Some(b)) = (self.candidates.get(*left), self.candidates.get(*right)) else {
            return true;
        };
        a.name == b.name
            || a.relations
                .conflicts()
                .iter()
                .chain(a.relations.breaks())
                .flat_map(|g| g.alternatives())
                .any(|relation| matches(b, relation))
    }
}
