//! Persist contextual reference graphs without claiming content verification.
use crate::{
    MetadataDb,
    publication::{FailurePoint, PublicationError, fail},
};
use dich_core::reference_graph::ReferenceGraph;
use rusqlite::{OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphOutcome {
    Published,
    Reused,
}
impl MetadataDb {
    /// Record one complete graph, requiring committed tree metadata for every node.
    /// This does not check bytes, activate packages, or create GC roots.
    pub fn put_reference_graph(
        &mut self,
        graph: &ReferenceGraph,
    ) -> Result<(String, GraphOutcome), PublicationError> {
        put_graph(self, graph, FailurePoint::None)
    }
}
pub(crate) fn put_graph(
    db: &mut MetadataDb,
    graph: &ReferenceGraph,
    failure: FailurePoint,
) -> Result<(String, GraphOutcome), PublicationError> {
    let id = Sha256::digest(graph.canonical())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let tx = db
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PublicationError::Database)?;
    for node in graph.nodes() {
        let present: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM verified_trees WHERE object_id = ?1)",
                [node],
                |row| row.get(0),
            )
            .map_err(|_| PublicationError::Database)?;
        if !present {
            return Err(PublicationError::Integrity);
        }
    }
    let old: Option<Vec<u8>> = tx
        .query_row(
            "SELECT manifest FROM reference_graphs WHERE graph_id = ?1",
            [&id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| PublicationError::Database)?;
    if let Some(old) = old {
        if old != graph.canonical() {
            return Err(PublicationError::Collision);
        }
        let mut query = tx
            .prepare(
                "SELECT object_id FROM reference_members WHERE graph_id = ?1 ORDER BY object_id",
            )
            .map_err(|_| PublicationError::Database)?;
        let rows = query
            .query_map([&id], |row| row.get::<_, String>(0))
            .map_err(|_| PublicationError::Database)?;
        let members: Result<Vec<_>, _> = rows.collect();
        if members.map_err(|_| PublicationError::Database)? != graph.nodes() {
            return Err(PublicationError::Integrity);
        }
        drop(query);
        tx.commit().map_err(|_| PublicationError::Database)?;
        return Ok((id, GraphOutcome::Reused));
    }
    tx.execute(
        "INSERT INTO reference_graphs (graph_id, manifest) VALUES (?1, ?2)",
        rusqlite::params![id, graph.canonical()],
    )
    .map_err(|_| PublicationError::Database)?;
    for node in graph.nodes() {
        tx.execute(
            "INSERT INTO reference_members (graph_id, object_id) VALUES (?1, ?2)",
            rusqlite::params![id, node],
        )
        .map_err(|_| PublicationError::Database)?;
    }
    fail(failure, FailurePoint::BeforeCommit)?;
    tx.commit().map_err(|_| PublicationError::Database)?;
    fail(failure, FailurePoint::AfterCommit)?;
    Ok((id, GraphOutcome::Published))
}
