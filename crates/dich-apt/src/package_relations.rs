//! Package relationship metadata; no dependency solving or host package inference.
use crate::{Comparison, ControlStanza, DependencyError, DependencyGroup, parse_dependencies};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiArch {
    No,
    Same,
    Foreign,
    Allowed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemBoundary {
    Essential,
    Required,
    Ordinary,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRelations {
    depends: Vec<DependencyGroup>,
    pre_depends: Vec<DependencyGroup>,
    conflicts: Vec<DependencyGroup>,
    provides: Vec<DependencyGroup>,
    breaks: Vec<DependencyGroup>,
    essential: bool,
    required_priority: bool,
    multi_arch: MultiArch,
    system_boundary: SystemBoundary,
}
impl PackageRelations {
    pub fn from_stanza(stanza: &ControlStanza) -> Result<Self, DependencyError> {
        let field = |name| {
            stanza
                .get(name)
                .map(parse_dependencies)
                .transpose()
                .map(Option::unwrap_or_default)
        };
        let depends = field("depends")?;
        let pre_depends = field("pre-depends")?;
        let conflicts: Vec<DependencyGroup> = field("conflicts")?;
        let provides: Vec<DependencyGroup> = field("provides")?;
        let breaks: Vec<DependencyGroup> = field("breaks")?;
        if conflicts
            .iter()
            .chain(&provides)
            .chain(&breaks)
            .any(|g| g.alternatives().len() != 1)
        {
            return Err(DependencyError);
        }
        if provides.iter().flat_map(|g| g.alternatives()).any(|r| {
            r.version()
                .is_some_and(|v| v.operator() != Comparison::Equal)
        }) {
            return Err(DependencyError);
        }
        let multi_arch = match stanza.get("multi-arch") {
            None | Some("no") => MultiArch::No,
            Some("same") => MultiArch::Same,
            Some("foreign") => MultiArch::Foreign,
            Some("allowed") => MultiArch::Allowed,
            _ => return Err(DependencyError),
        };
        let essential = match stanza.get("essential") {
            None | Some("no") => false,
            Some("yes") => true,
            _ => return Err(DependencyError),
        };
        let required = match stanza.get("priority") {
            None | Some("important" | "standard" | "optional" | "extra") => false,
            Some("required") => true,
            _ => return Err(DependencyError),
        };
        let system_boundary = if essential {
            SystemBoundary::Essential
        } else if required {
            SystemBoundary::Required
        } else {
            SystemBoundary::Ordinary
        };
        Ok(Self {
            depends,
            pre_depends,
            conflicts,
            provides,
            breaks,
            essential,
            required_priority: required,
            multi_arch,
            system_boundary,
        })
    }
    pub fn depends(&self) -> &[DependencyGroup] {
        &self.depends
    }
    pub fn pre_depends(&self) -> &[DependencyGroup] {
        &self.pre_depends
    }
    pub fn conflicts(&self) -> &[DependencyGroup] {
        &self.conflicts
    }
    pub fn breaks(&self) -> &[DependencyGroup] {
        &self.breaks
    }
    pub fn essential(&self) -> bool {
        self.essential
    }
    pub fn required_priority(&self) -> bool {
        self.required_priority
    }
    pub fn provides(&self) -> &[DependencyGroup] {
        &self.provides
    }
    pub fn multi_arch(&self) -> MultiArch {
        self.multi_arch
    }
    pub fn system_boundary(&self) -> SystemBoundary {
        self.system_boundary
    }
}
