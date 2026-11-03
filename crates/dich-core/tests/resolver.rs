use dich_core::resolver::{Provider, ResolveError, SearchLimits, resolve};

struct Graph;
impl Provider for Graph {
    type Candidate = &'static str;
    type Requirement = &'static str;
    fn candidates(&self, requirement: &Self::Requirement) -> Vec<Self::Candidate> {
        match *requirement {
            "root" => vec!["root"],
            "lib" => vec!["lib2", "lib1"],
            "extra" => vec!["extra"],
            "cycle" => vec!["root"],
            "missing" => vec![],
            _ => vec![],
        }
    }
    fn requirements(&self, candidate: &Self::Candidate) -> Vec<Self::Requirement> {
        match *candidate {
            "root" => vec!["lib", "extra"],
            "lib1" => vec!["cycle"],
            "extra" => vec![],
            _ => vec![],
        }
    }
    fn incompatible(&self, left: &Self::Candidate, right: &Self::Candidate) -> bool {
        (*left == "lib2" && *right == "extra") || (*right == "lib2" && *left == "extra")
    }
}

#[test]
fn backtracks_deterministically_and_satisfies_cycles() {
    let result = resolve(&Graph, vec!["root"], SearchLimits::default()).unwrap();
    assert_eq!(result.selected, vec!["root", "lib1", "extra"]);
    assert!(
        result
            .trace
            .iter()
            .any(|s| s.contains("extra") && s.contains("lib2") && s.contains("conflict"))
    );
    assert!(
        result
            .trace
            .iter()
            .any(|s| s.contains("already selected") && s.contains("root"))
    );
}

#[test]
fn missing_or_exhausted_search_never_returns_partial_plan() {
    assert!(matches!(
        resolve(&Graph, vec!["missing"], SearchLimits::default()),
        Err(ResolveError::Unsatisfiable { .. })
    ));
    assert!(matches!(
        resolve(
            &Graph,
            vec!["root"],
            SearchLimits {
                max_steps: 1,
                max_selected: 10
            }
        ),
        Err(ResolveError::LimitExceeded)
    ));
}
