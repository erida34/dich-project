use dich_core::reference_graph::{GraphError, ReferenceGraph};
fn id(c: char) -> String {
    c.to_string().repeat(64)
}
#[test]
fn graph_identity_is_canonical_and_supports_cycles_and_isolated_roots() {
    let (a, b, c) = (id('a'), id('b'), id('c'));
    let first = ReferenceGraph::new(&[&a, &c], &[(&a, &b), (&b, &a)]).unwrap();
    let second = ReferenceGraph::new(&[&c, &a], &[(&b, &a), (&a, &b)]).unwrap();
    assert_eq!(first.canonical(), second.canonical());
    assert_eq!(first.nodes().len(), 3);
    assert_eq!(first.roots().len(), 2);
    assert_eq!(first.edges().len(), 2);
}
#[test]
fn malformed_duplicates_self_edges_and_disconnected_nodes_fail() {
    let (a, b, c) = (id('a'), id('b'), id('c'));
    assert_eq!(
        ReferenceGraph::new(&[], &[]).unwrap_err(),
        GraphError::MissingRoot
    );
    assert_eq!(
        ReferenceGraph::new(&["bad"], &[]).unwrap_err(),
        GraphError::InvalidId
    );
    assert_eq!(
        ReferenceGraph::new(&[&a, &a], &[]).unwrap_err(),
        GraphError::Duplicate
    );
    assert_eq!(
        ReferenceGraph::new(&[&a], &[(&a, &b), (&a, &b)]).unwrap_err(),
        GraphError::Duplicate
    );
    assert_eq!(
        ReferenceGraph::new(&[&a], &[(&a, &a)]).unwrap_err(),
        GraphError::SelfEdge
    );
    assert_eq!(
        ReferenceGraph::new(&[&a], &[(&b, &c)]).unwrap_err(),
        GraphError::Disconnected
    );
    assert_eq!(
        ReferenceGraph::new(&[&a.to_uppercase()], &[]).unwrap_err(),
        GraphError::InvalidId
    );
}
#[test]
fn graph_size_is_bounded() {
    let a = id('a');
    let roots = vec![a.as_str(); 10_001];
    assert_eq!(
        ReferenceGraph::new(&roots, &[]).unwrap_err(),
        GraphError::Limit
    );
}

#[test]
fn single_root_has_stable_domain_separated_encoding() {
    let a = id('a');
    let graph = ReferenceGraph::new(&[&a], &[]).unwrap();
    let mut expected = b"dich.reference-graph\0v1\0".to_vec();
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(a.as_bytes());
    expected.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(graph.canonical(), expected);
}
