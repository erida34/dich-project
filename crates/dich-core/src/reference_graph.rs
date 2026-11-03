//! Bounded contextual graph snapshots; no store access or authorization.
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};
const MAX_NODES: usize = 10_000;
const MAX_EDGES: usize = 40_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphError {
    MissingRoot,
    InvalidId,
    InvalidEncoding,
    Duplicate,
    SelfEdge,
    Disconnected,
    Limit,
}
impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reference graph rejected: {self:?}")
    }
}
impl Error for GraphError {}
/// Canonical graph; membership describes dependencies, not trust or runtime compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceGraph {
    roots: Vec<String>,
    edges: Vec<(String, String)>,
    nodes: Vec<String>,
    canonical: Vec<u8>,
}
fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl ReferenceGraph {
    pub fn new(roots: &[&str], edges: &[(&str, &str)]) -> Result<Self, GraphError> {
        if roots.is_empty() {
            return Err(GraphError::MissingRoot);
        }
        if roots.len() > MAX_NODES || edges.len() > MAX_EDGES {
            return Err(GraphError::Limit);
        }
        let mut root_set = BTreeSet::new();
        let mut edge_set = BTreeSet::new();
        let mut nodes = BTreeSet::new();
        let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for &root in roots {
            if !valid_id(root) {
                return Err(GraphError::InvalidId);
            }
            if !root_set.insert(root) {
                return Err(GraphError::Duplicate);
            }
            nodes.insert(root);
        }
        for &(from, to) in edges {
            if !valid_id(from) || !valid_id(to) {
                return Err(GraphError::InvalidId);
            }
            if from == to {
                return Err(GraphError::SelfEdge);
            }
            if !edge_set.insert((from, to)) {
                return Err(GraphError::Duplicate);
            }
            nodes.insert(from);
            nodes.insert(to);
            if nodes.len() > MAX_NODES {
                return Err(GraphError::Limit);
            }
            adjacency.entry(from).or_default().push(to);
        }
        let mut reachable = BTreeSet::new();
        let mut pending: Vec<_> = root_set.iter().copied().collect();
        while let Some(node) = pending.pop() {
            if reachable.insert(node) {
                if let Some(children) = adjacency.get(node) {
                    pending.extend(children.iter().copied());
                }
            }
        }
        if reachable.len() != nodes.len() {
            return Err(GraphError::Disconnected);
        }
        let mut canonical = b"dich.reference-graph\0v1\0".to_vec();
        canonical.extend_from_slice(&(root_set.len() as u32).to_be_bytes());
        for root in &root_set {
            canonical.extend_from_slice(root.as_bytes());
        }
        canonical.extend_from_slice(&(edge_set.len() as u32).to_be_bytes());
        for (from, to) in &edge_set {
            canonical.extend_from_slice(from.as_bytes());
            canonical.extend_from_slice(to.as_bytes());
        }
        Ok(Self {
            roots: root_set.into_iter().map(str::to_owned).collect(),
            edges: edge_set
                .into_iter()
                .map(|(a, b)| (a.to_owned(), b.to_owned()))
                .collect(),
            nodes: nodes.into_iter().map(str::to_owned).collect(),
            canonical,
        })
    }
    /// Decode only an exact canonical representation; hostile inputs are bounded.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, GraphError> {
        use std::io::{Cursor, Read};
        const PREFIX: &[u8] = b"dich.reference-graph\0v1\0";
        if !bytes.starts_with(PREFIX)
            || bytes.len() > PREFIX.len() + 8 + MAX_NODES * 64 + MAX_EDGES * 128
        {
            return Err(GraphError::InvalidEncoding);
        }
        fn read_count(c: &mut Cursor<&[u8]>) -> Result<usize, GraphError> {
            let mut b = [0; 4];
            c.read_exact(&mut b)
                .map_err(|_| GraphError::InvalidEncoding)?;
            Ok(u32::from_be_bytes(b) as usize)
        }
        fn read_id(c: &mut Cursor<&[u8]>) -> Result<String, GraphError> {
            let mut b = [0; 64];
            c.read_exact(&mut b)
                .map_err(|_| GraphError::InvalidEncoding)?;
            String::from_utf8(b.to_vec()).map_err(|_| GraphError::InvalidEncoding)
        }
        let mut c = Cursor::new(&bytes[PREFIX.len()..]);
        let roots_count = read_count(&mut c)?;
        if roots_count == 0 || roots_count > MAX_NODES {
            return Err(GraphError::InvalidEncoding);
        }
        let mut roots = Vec::with_capacity(roots_count);
        for _ in 0..roots_count {
            roots.push(read_id(&mut c)?);
        }
        let edge_count = read_count(&mut c)?;
        if edge_count > MAX_EDGES {
            return Err(GraphError::InvalidEncoding);
        }
        let mut edges = Vec::with_capacity(edge_count);
        for _ in 0..edge_count {
            edges.push((read_id(&mut c)?, read_id(&mut c)?));
        }
        if c.position() != (bytes.len() - PREFIX.len()) as u64 {
            return Err(GraphError::InvalidEncoding);
        }
        let roots_ref: Vec<_> = roots.iter().map(String::as_str).collect();
        let edges_ref: Vec<_> = edges
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let result = Self::new(&roots_ref, &edges_ref)?;
        if result.canonical != bytes {
            return Err(GraphError::InvalidEncoding);
        }
        Ok(result)
    }
    pub fn roots(&self) -> &[String] {
        &self.roots
    }
    pub fn edges(&self) -> &[(String, String)] {
        &self.edges
    }
    pub fn nodes(&self) -> &[String] {
        &self.nodes
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
}
