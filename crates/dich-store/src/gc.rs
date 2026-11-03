//! Mark-and-sweep garbage collection of unreachable store objects.
use crate::{
    MetadataDb,
    publication::{PublicationError, private_dir},
    recovery::delete_tree_object,
};
use rusqlite::TransactionBehavior;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcMode {
    DryRun,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreachableTree {
    pub object_id: String,
    pub total_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreachableGraph {
    pub graph_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcRootsReport {
    pub active_profiles: Vec<String>,
    pub reachable_tree_count: usize,
    pub reachable_graph_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    pub mode: GcMode,
    pub roots: GcRootsReport,
    pub unreachable_trees: Vec<UnreachableTree>,
    pub unreachable_graphs: Vec<UnreachableGraph>,
    pub reclaimable_bytes: u64,
    pub reclaimed_bytes: u64,
    pub retained_trees: usize,
    pub retained_graphs: usize,
}

impl MetadataDb {
    /// Mark-and-sweep garbage collection from profiles, pins, and active leases.
    /// In `DryRun` mode (default), calculates unreachable objects and reclaimable bytes
    /// without making any mutations to store files or SQLite metadata.
    /// In `Execute` mode, under the exclusive store lock, safely deletes unreachable trees
    /// from `objects/` using descriptor-relative non-symlink traversal, unlinks directories
    /// with fsync, and deletes metadata rows from `verified_trees`, `reference_members`,
    /// and `reference_graphs`.
    pub fn collect_garbage(&mut self, mode: GcMode) -> Result<GcReport, PublicationError> {
        let roots = self.collect_roots()?;

        let mut unreachable_trees = Vec::new();
        let mut total_trees_count = 0;
        let mut reclaimable_bytes = 0u64;

        {
            let mut stmt = self
                .connection
                .prepare("SELECT object_id, total_size FROM verified_trees ORDER BY object_id")
                .map_err(|_| PublicationError::Database)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(|_| PublicationError::Database)?;

            for row in rows {
                let (object_id, total_size) = row.map_err(|_| PublicationError::Database)?;
                total_trees_count += 1;
                if !roots.reachable_trees.contains(&object_id) {
                    let size = if total_size > 0 { total_size as u64 } else { 0 };
                    reclaimable_bytes += size;
                    unreachable_trees.push(UnreachableTree {
                        object_id,
                        total_size: size,
                    });
                }
            }
        }

        // Sweep reference_graphs
        let mut unreachable_graphs = Vec::new();
        let mut total_graphs_count = 0;

        {
            let mut stmt = self
                .connection
                .prepare("SELECT graph_id FROM reference_graphs ORDER BY graph_id")
                .map_err(|_| PublicationError::Database)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|_| PublicationError::Database)?;

            for row in rows {
                let graph_id = row.map_err(|_| PublicationError::Database)?;
                total_graphs_count += 1;
                if !roots.reachable_graphs.contains(&graph_id) {
                    unreachable_graphs.push(UnreachableGraph { graph_id });
                }
            }
        }

        let retained_trees = total_trees_count - unreachable_trees.len();
        let retained_graphs = total_graphs_count - unreachable_graphs.len();

        let roots_report = GcRootsReport {
            active_profiles: roots.active_profiles,
            reachable_tree_count: roots.reachable_trees.len(),
            reachable_graph_count: roots.reachable_graphs.len(),
        };

        match mode {
            GcMode::DryRun => Ok(GcReport {
                mode: GcMode::DryRun,
                roots: roots_report,
                unreachable_trees,
                unreachable_graphs,
                reclaimable_bytes,
                reclaimed_bytes: 0,
                retained_trees,
                retained_graphs,
            }),
            GcMode::Execute => {
                let objects = private_dir(&self.root, "objects")?;
                let mut reclaimed_bytes = 0u64;
                for tree in &unreachable_trees {
                    delete_tree_object(&objects, &tree.object_id)?;
                    reclaimed_bytes += tree.total_size;
                }

                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|_| PublicationError::Database)?;
                for tree in &unreachable_trees {
                    tx.execute(
                        "DELETE FROM reference_members WHERE object_id = ?1",
                        [&tree.object_id],
                    )
                    .map_err(|_| PublicationError::Database)?;
                    tx.execute(
                        "DELETE FROM verified_trees WHERE object_id = ?1",
                        [&tree.object_id],
                    )
                    .map_err(|_| PublicationError::Database)?;
                }
                for graph in &unreachable_graphs {
                    tx.execute(
                        "DELETE FROM reference_members WHERE graph_id = ?1",
                        [&graph.graph_id],
                    )
                    .map_err(|_| PublicationError::Database)?;
                    tx.execute(
                        "DELETE FROM reference_graphs WHERE graph_id = ?1",
                        [&graph.graph_id],
                    )
                    .map_err(|_| PublicationError::Database)?;
                }
                tx.commit().map_err(|_| PublicationError::Database)?;

                Ok(GcReport {
                    mode: GcMode::Execute,
                    roots: roots_report,
                    unreachable_trees,
                    unreachable_graphs,
                    reclaimable_bytes,
                    reclaimed_bytes,
                    retained_trees,
                    retained_graphs,
                })
            }
        }
    }
}
