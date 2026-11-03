//! Experimental fixture provider; not connected to authenticated sources or CLI plans.
use crate::{
    Comparison, ControlStanza, DebianVersion, DependencyGroup, DependencyRelation, MultiArch,
    PackageRelations, SystemBoundary, parse_dependencies,
};
use dich_core::resolver::{Provider, ValidationError};
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
    /// An explicit test-only baseline prevents implicit downgrades; it is not read from host state.
    pub fn from_stanzas_with_baseline(
        stanzas: &[ControlStanza],
        architecture: &str,
        baseline: &[(&str, &str)],
    ) -> Result<Self, UniverseError> {
        if baseline.len() > 100_000 {
            return Err(UniverseError);
        }
        let mut versions = BTreeMap::new();
        for (name, version) in baseline {
            let parsed = parse_dependencies(name).map_err(|_| UniverseError)?;
            if parsed.len() != 1
                || parsed[0].alternatives().len() != 1
                || parsed[0].alternatives()[0].name() != *name
            {
                return Err(UniverseError);
            }
            let version = DebianVersion::parse(version).map_err(|_| UniverseError)?;
            if versions.insert(*name, version).is_some() {
                return Err(UniverseError);
            }
        }
        let mut universe = Self::from_stanzas(stanzas, architecture)?;
        for candidate in &mut universe.candidates {
            if versions
                .get(candidate.name.as_str())
                .is_some_and(|version| candidate.version < *version)
            {
                candidate.supported = false;
            }
        }
        Ok(universe)
    }
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
            let simple_depends = relations
                .depends()
                .iter()
                .chain(relations.pre_depends())
                .flat_map(|g| g.alternatives())
                .all(|r| {
                    matches!(r.qualifier(), None | Some("any"))
                        && r.architectures().is_empty()
                        && r.profiles().is_empty()
                });
            let supported = (arch == architecture || arch == "all")
                && relations.system_boundary() == SystemBoundary::Ordinary
                && !(arch == "all" && relations.multi_arch() == MultiArch::Same)
                && simple_depends
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
    pub fn require_exact(&self, name: &str, version: &str) -> Result<Requirement, UniverseError> {
        let parsed_version = DebianVersion::parse(version).map_err(|_| UniverseError)?;
        let expression = format!("{name} (= {version})");
        let parsed = parse_dependencies(&expression).map_err(|_| UniverseError)?;
        if parsed.len() != 1 || parsed[0].alternatives().len() != 1 {
            return Err(UniverseError);
        }
        let relation = &parsed[0].alternatives()[0];
        let exact = relation.version().is_some_and(|constraint| {
            constraint.operator() == Comparison::Equal && constraint.version() == &parsed_version
        });
        if relation.name() != name || !exact {
            return Err(UniverseError);
        }
        Ok(Requirement(vec![relation.clone()]))
    }
    pub(crate) fn identity(&self, id: usize) -> Option<(String, String)> {
        let c = self.candidates.get(id)?;
        Some((c.name.clone(), c.version.as_str().to_owned()))
    }
    pub fn label(&self, id: usize) -> Option<String> {
        let c = self.candidates.get(id)?;
        Some(format!("{}={}", c.name, c.version.as_str()))
    }
    pub(crate) fn solution_graph(
        &self,
        requested: &Requirement,
        selected: &[usize],
    ) -> Result<(String, Vec<(String, String)>), UniverseError> {
        let roots: Vec<_> = selected
            .iter()
            .enumerate()
            .filter(|(_, id)| {
                let Some(candidate) = self.candidates.get(**id) else {
                    return false;
                };
                requested
                    .0
                    .iter()
                    .any(|relation| dependency_matches(candidate, relation))
            })
            .map(|(index, _)| index)
            .collect();
        if roots.len() != 1 {
            return Err(UniverseError);
        }

        let mut edges = BTreeSet::new();
        for (from, id) in selected.iter().enumerate() {
            let candidate = self.candidates.get(*id).ok_or(UniverseError)?;
            for group in candidate
                .relations
                .pre_depends()
                .iter()
                .chain(candidate.relations.depends())
            {
                let matches: Vec<_> = selected
                    .iter()
                    .enumerate()
                    .filter(|(_, target_id)| {
                        let Some(target) = self.candidates.get(**target_id) else {
                            return false;
                        };
                        group
                            .alternatives()
                            .iter()
                            .any(|relation| dependency_matches(target, relation))
                    })
                    .map(|(index, _)| index)
                    .collect();
                if matches.len() != 1 {
                    return Err(UniverseError);
                }
                edges.insert((from, matches[0]));
            }
        }

        let label = |index: usize| {
            selected
                .get(index)
                .and_then(|id| self.label(*id))
                .ok_or(UniverseError)
        };
        let root = label(roots[0])?;
        let edges = edges
            .into_iter()
            .map(|(from, to)| Ok((label(from)?, label(to)?)))
            .collect::<Result<Vec<_>, UniverseError>>()?;
        Ok((root, edges))
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
    if candidate.name == relation.name() {
        return compare(&candidate.version, relation);
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
fn dependency_matches(candidate: &Candidate, relation: &DependencyRelation) -> bool {
    if !matches(candidate, relation) {
        return false;
    }
    match relation.qualifier() {
        None => true,
        Some("any") => {
            candidate.name == relation.name()
                && candidate.relations.multi_arch() == MultiArch::Allowed
        }
        Some(_) => false,
    }
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
                if candidate.supported
                    && dependency_matches(candidate, relation)
                    && !seen.contains(id)
                {
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
                    matches(candidate, relation)
                        && (!candidate.supported
                            || (relation.qualifier() == Some("any")
                                && candidate.name != relation.name()))
                })
        })
    }
    fn requirements(&self, candidate: &usize) -> Vec<Requirement> {
        let Some(candidate) = self.candidates.get(*candidate) else {
            return vec![Requirement(Vec::new())];
        };
        candidate
            .relations
            .pre_depends()
            .iter()
            .chain(candidate.relations.depends())
            .map(|group| Requirement(group.alternatives().to_vec()))
            .collect()
    }
    fn validate_solution(&self, selected: &[usize]) -> Result<(), ValidationError> {
        let mut edges: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); selected.len()];
        let mut pre_edges = BTreeSet::new();
        let mut checks = 0usize;
        for (from, id) in selected.iter().enumerate() {
            let candidate = self
                .candidates
                .get(*id)
                .ok_or_else(|| ValidationError::Unsupported("invalid candidate".into()))?;
            for (is_pre, group) in candidate
                .relations
                .pre_depends()
                .iter()
                .map(|g| (true, g))
                .chain(candidate.relations.depends().iter().map(|g| (false, g)))
            {
                let mut found = false;
                for (to, selected_id) in selected.iter().enumerate() {
                    checks += 1;
                    if checks > 10_000 {
                        return Err(ValidationError::Limit);
                    }
                    let target = self
                        .candidates
                        .get(*selected_id)
                        .ok_or_else(|| ValidationError::Unsupported("invalid candidate".into()))?;
                    if group
                        .alternatives()
                        .iter()
                        .any(|r| dependency_matches(target, r))
                    {
                        found = true;
                        edges[from].insert(to);
                        if is_pre {
                            pre_edges.insert((from, to));
                        }
                    }
                }
                if !found {
                    return Err(ValidationError::Unsupported(
                        "selected package has an unsatisfied dependency".into(),
                    ));
                }
            }
        }
        let mut traversal_steps = 0usize;
        for (from, to) in pre_edges {
            let mut visited = BTreeSet::new();
            let mut pending = vec![to];
            while let Some(node) = pending.pop() {
                traversal_steps += 1;
                if traversal_steps > 100_000 {
                    return Err(ValidationError::Limit);
                }
                if node == from {
                    return Err(ValidationError::Unsupported(format!(
                        "unsupported Pre-Depends cycle involving {}",
                        self.label(selected[from])
                            .unwrap_or_else(|| "invalid candidate".into())
                    )));
                }
                if visited.insert(node) {
                    pending.extend(edges[node].iter().copied());
                }
            }
        }
        Ok(())
    }
    fn describe_candidate(&self, candidate: &usize) -> String {
        self.label(*candidate)
            .unwrap_or_else(|| "invalid candidate".into())
    }
    fn describe_requirement(&self, requirement: &Requirement) -> String {
        requirement
            .0
            .iter()
            .map(|relation| {
                let mut result = relation.name().to_owned();
                if let Some(qualifier) = relation.qualifier() {
                    result.push(':');
                    result.push_str(qualifier);
                }
                if let Some(version) = relation.version() {
                    let operator = match version.operator() {
                        Comparison::Less => "<<",
                        Comparison::LessOrEqual => "<=",
                        Comparison::Equal => "=",
                        Comparison::GreaterOrEqual => ">=",
                        Comparison::Greater => ">>",
                    };
                    result.push_str(&format!(" ({operator} {})", version.version().as_str()));
                }
                result
            })
            .collect::<Vec<_>>()
            .join(" | ")
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

#[cfg(test)]
mod solution_graph_tests {
    use super::*;
    use crate::parse_control_stanzas;
    use dich_core::resolver::{SearchLimits, resolve};

    #[test]
    fn selected_dependencies_form_one_exact_rooted_graph() {
        let stanzas = parse_control_stanzas(
            b"Package: app\nVersion: 1\nArchitecture: amd64\nDepends: lib\n\nPackage: lib\nVersion: 2\nArchitecture: amd64\nDepends: base\n\nPackage: base\nVersion: 3\nArchitecture: amd64\n",
        )
        .unwrap();
        let universe = DebianUniverse::from_stanzas(&stanzas, "amd64").unwrap();
        let request = universe.require("app").unwrap();
        let solution = resolve(&universe, vec![request.clone()], SearchLimits::default()).unwrap();
        let (root, edges) = universe
            .solution_graph(&request, &solution.selected)
            .unwrap();
        assert_eq!(root, "app=1");
        assert_eq!(
            edges,
            vec![
                ("app=1".into(), "lib=2".into()),
                ("lib=2".into(), "base=3".into())
            ]
        );
    }

    #[test]
    fn ambiguous_selected_alternatives_are_not_written_as_dependency_edges() {
        let stanzas = parse_control_stanzas(
            b"Package: app\nVersion: 1\nArchitecture: amd64\nDepends: left | right, extra\n\nPackage: left\nVersion: 1\nArchitecture: amd64\nDepends: extra\n\nPackage: right\nVersion: 1\nArchitecture: amd64\nDepends: extra\n\nPackage: extra\nVersion: 1\nArchitecture: amd64\n",
        )
        .unwrap();
        let universe = DebianUniverse::from_stanzas(&stanzas, "amd64").unwrap();
        let request = universe.require("app").unwrap();
        let selected = vec![
            universe.names["app"][0],
            universe.names["left"][0],
            universe.names["right"][0],
            universe.names["extra"][0],
        ];
        assert!(universe.solution_graph(&request, &selected).is_err());
    }
}
