//! Metadata-only inspection; never represents contents as verified.
use crate::{MetadataDb, publication::PublicationError};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Archive,
    Tree,
}
/// A committed metadata record. The object bytes have not been checked by inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRecord {
    pub id: String,
    pub kind: ObjectKind,
    pub stored_bytes: u64,
}
fn record(
    id: String,
    kind: ObjectKind,
    stored: i64,
    context: Vec<u8>,
    digest: Option<Vec<u8>>,
) -> Result<ObjectRecord, PublicationError> {
    let (artifact_size, artifact_hash) = crate::verify_identity_context(
        &id,
        &context,
        match kind {
            ObjectKind::Archive => 2,
            ObjectKind::Tree => 1,
        },
    )?;
    if stored < 0 {
        return Err(PublicationError::Integrity);
    }
    match kind {
        ObjectKind::Archive => {
            if stored as u64 != artifact_size
                || stored == 0
                || stored as u64 > 256 * 1024 * 1024
                || digest.as_deref() != Some(artifact_hash.as_slice())
            {
                return Err(PublicationError::Integrity);
            }
        }
        ObjectKind::Tree => {
            if stored as u64 > 128 * 1024 * 1024 || digest.is_some() {
                return Err(PublicationError::Integrity);
            }
        }
    }
    Ok(ObjectRecord {
        id,
        kind,
        stored_bytes: stored as u64,
    })
}
impl MetadataDb {
    /// List bounded committed metadata records. Does not verify stored bytes.
    pub fn list_objects(&self) -> Result<Vec<ObjectRecord>, PublicationError> {
        let mut query = self.connection.prepare("SELECT object_id, 0 AS kind, artifact_size, manifest, artifact_sha256 FROM verified_archives UNION ALL SELECT object_id, 1 AS kind, total_size, manifest, NULL FROM verified_trees ORDER BY object_id, kind LIMIT 50001").map_err(|_| PublicationError::Database)?;
        let mut rows = query.query([]).map_err(|_| PublicationError::Database)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|_| PublicationError::Database)? {
            if result.len() >= 50_000 {
                return Err(PublicationError::Limit);
            }
            let id = row.get(0).map_err(|_| PublicationError::Database)?;
            let kind: i64 = row.get(1).map_err(|_| PublicationError::Database)?;
            let kind = match kind {
                0 => ObjectKind::Archive,
                1 => ObjectKind::Tree,
                _ => return Err(PublicationError::Integrity),
            };
            result.push(record(
                id,
                kind,
                row.get(2).map_err(|_| PublicationError::Database)?,
                row.get(3).map_err(|_| PublicationError::Database)?,
                row.get(4).map_err(|_| PublicationError::Database)?,
            )?);
        }
        Ok(result)
    }
    /// Inspect committed metadata. Does not verify stored bytes.
    pub fn inspect_object(
        &self,
        id: &str,
        kind: ObjectKind,
    ) -> Result<ObjectRecord, PublicationError> {
        let sql = match kind {
            ObjectKind::Archive => {
                "SELECT artifact_size, manifest, artifact_sha256 FROM verified_archives WHERE object_id = ?1"
            }
            ObjectKind::Tree => {
                "SELECT total_size, manifest, NULL FROM verified_trees WHERE object_id = ?1"
            }
        };
        let (size, context, digest): (i64, Vec<u8>, Option<Vec<u8>>) = self
            .connection
            .query_row(sql, [id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|_| PublicationError::Integrity)?;
        record(id.to_owned(), kind, size, context, digest)
    }
}
