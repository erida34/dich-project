//! Read-only, bounded crash-remnant inventory under the exclusive store lock.
use crate::{
    MetadataDb,
    publication::{PublicationError, private_dir},
};
use rustix::fs::{self, AtFlags, FileType};
use std::{collections::BTreeSet, os::fd::OwnedFd};

/// Names only; inventory does not verify content or remove anything.
#[derive(Debug, Default)]
pub struct RecoveryInventory {
    pub staged: Vec<String>,
    pub orphan_archives: Vec<String>,
    pub orphan_trees: Vec<String>,
    pub missing_archives: Vec<String>,
    pub missing_trees: Vec<String>,
    pub unexpected: Vec<String>,
}
fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn names(dir: &OwnedFd) -> Result<Vec<(String, FileType)>, PublicationError> {
    let mut result = Vec::new();
    let mut reader = fs::Dir::read_from(dir).map_err(|_| PublicationError::Io)?;
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(|_| PublicationError::Io)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| PublicationError::Integrity)?;
        if name == "." || name == ".." {
            continue;
        }
        if result.len() >= 50_000 {
            return Err(PublicationError::Limit);
        }
        let stat =
            fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| PublicationError::Io)?;
        result.push((name.to_owned(), FileType::from_raw_mode(stat.st_mode)));
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}
impl MetadataDb {
    /// Enumerate leftovers and metadata references. Does not authenticate listed content.
    pub fn recovery_inventory(&self) -> Result<RecoveryInventory, PublicationError> {
        let staging = private_dir(&self.root, "staging")?;
        let objects = private_dir(&self.root, "objects")?;
        let mut inventory = RecoveryInventory::default();
        for (name, kind) in names(&staging)? {
            let recognized = name
                .strip_prefix("tree-")
                .is_some_and(|v| valid_hex(v, 32) && kind == FileType::Directory)
                || name
                    .strip_prefix("stage-")
                    .is_some_and(|v| valid_hex(v, 32) && kind == FileType::RegularFile);
            if recognized {
                inventory.staged.push(name);
            } else {
                inventory.unexpected.push(format!("staging/{name}"));
            }
        }
        let mut archives = BTreeSet::new();
        let mut trees = BTreeSet::new();
        for (name, kind) in names(&objects)? {
            if let Some(id) = name
                .strip_suffix(".deb")
                .filter(|id| valid_hex(id, 64) && kind == FileType::RegularFile)
            {
                archives.insert(id.to_owned());
            } else if let Some(id) = name
                .strip_suffix(".tree")
                .filter(|id| valid_hex(id, 64) && kind == FileType::Directory)
            {
                trees.insert(id.to_owned());
            } else {
                inventory.unexpected.push(format!("objects/{name}"));
            }
        }
        let mut stmt = self
            .connection
            .prepare("SELECT object_id FROM verified_archives")
            .map_err(|_| PublicationError::Database)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| PublicationError::Database)?;
        for (index, row) in rows.enumerate() {
            if index >= 50_000 {
                return Err(PublicationError::Limit);
            }
            let id = row.map_err(|_| PublicationError::Database)?;
            if !valid_hex(&id, 64) {
                return Err(PublicationError::Integrity);
            }
            if !archives.remove(&id) {
                inventory.missing_archives.push(id);
            }
        }
        let mut stmt = self
            .connection
            .prepare("SELECT object_id FROM verified_trees")
            .map_err(|_| PublicationError::Database)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| PublicationError::Database)?;
        for (index, row) in rows.enumerate() {
            if index >= 50_000 {
                return Err(PublicationError::Limit);
            }
            let id = row.map_err(|_| PublicationError::Database)?;
            if !valid_hex(&id, 64) {
                return Err(PublicationError::Integrity);
            }
            if !trees.remove(&id) {
                inventory.missing_trees.push(id);
            }
        }
        inventory.orphan_archives = archives.into_iter().collect();
        inventory.orphan_trees = trees.into_iter().collect();
        inventory.missing_archives.sort();
        inventory.missing_trees.sort();
        inventory.unexpected.sort();
        Ok(inventory)
    }
}
