//! Read-only, bounded crash-remnant inventory under the exclusive store lock.
use crate::{
    MetadataDb,
    publication::{PublicationError, private_dir},
};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::process::geteuid;
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

fn open_child(dir: &OwnedFd, name: &str, is_dir: bool) -> Result<OwnedFd, PublicationError> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if is_dir {
        flags |= OFlags::DIRECTORY;
    }
    fs::openat2(
        dir,
        name,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| PublicationError::UnsafePath)
}
fn check_entry(fd: &OwnedFd, is_dir: bool, device: u64) -> Result<(), PublicationError> {
    let stat = fs::fstat(fd).map_err(|_| PublicationError::Io)?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    if stat.st_dev != device
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || if is_dir {
            kind != FileType::Directory || stat.st_mode & 0o7777 != 0o700
        } else {
            kind != FileType::RegularFile
                || stat.st_nlink != 1
                || !matches!(stat.st_mode & 0o7777, 0o400 | 0o600)
        }
    {
        return Err(PublicationError::Integrity);
    }
    Ok(())
}
fn visit(
    dir: &OwnedFd,
    device: u64,
    depth: usize,
    remaining: &mut usize,
    remove: bool,
) -> Result<(), PublicationError> {
    if depth > 128 {
        return Err(PublicationError::Limit);
    }
    check_entry(dir, true, device)?;
    for (name, kind) in names(dir)? {
        *remaining = remaining.checked_sub(1).ok_or(PublicationError::Limit)?;
        let is_dir = match kind {
            FileType::Directory => true,
            FileType::RegularFile => false,
            _ => return Err(PublicationError::UnsafePath),
        };
        let fd = open_child(dir, &name, is_dir)?;
        check_entry(&fd, is_dir, device)?;
        if is_dir {
            visit(&fd, device, depth + 1, remaining, remove)?;
        }
        if remove {
            fs::unlinkat(
                dir,
                &name,
                if is_dir {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                },
            )
            .map_err(|_| PublicationError::Io)?;
            #[cfg(test)]
            if std::env::var_os("DICH_INJECT_CLEANUP_EXIT").is_some() {
                std::process::exit(87);
            }
        }
    }
    if remove {
        fs::fsync(dir).map_err(|_| PublicationError::Io)?;
    }
    Ok(())
}
impl MetadataDb {
    /// Explicitly remove one recognized incomplete staging entry. No object or metadata row is removed.
    /// A failure can leave a partially removed entry; retry is safe under the store lock.
    pub fn remove_staged(&mut self, name: &str) -> Result<(), PublicationError> {
        let tree = name.strip_prefix("tree-").is_some_and(|v| valid_hex(v, 32));
        let archive = name
            .strip_prefix("stage-")
            .is_some_and(|v| valid_hex(v, 32));
        if !tree && !archive {
            return Err(PublicationError::UnsafePath);
        }
        let staging = private_dir(&self.root, "staging")?;
        let fd = match open_child(&staging, name, tree) {
            Ok(fd) => fd,
            Err(_) => return Err(PublicationError::UnsafePath),
        };
        let device = fs::fstat(&staging)
            .map_err(|_| PublicationError::Io)?
            .st_dev;
        check_entry(&fd, tree, device)?;
        if tree {
            visit(&fd, device, 0, &mut 35_000, false)?;
            visit(&fd, device, 0, &mut 35_000, true)?;
        }
        fs::unlinkat(
            &staging,
            name,
            if tree {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        )
        .map_err(|_| PublicationError::Io)?;
        fs::fsync(&staging).map_err(|_| PublicationError::Io)?;
        Ok(())
    }
}

/// Kind of unreferenced publication to remove explicitly.
#[derive(Debug, Clone, Copy)]
pub enum OrphanKind {
    Archive,
    Tree,
}
impl MetadataDb {
    /// Remove one unreferenced object. The lock protects the metadata check and removal.
    /// This is not garbage collection; future reference types must be checked before extending it.
    pub fn remove_orphan(&mut self, id: &str, kind: OrphanKind) -> Result<(), PublicationError> {
        if !valid_hex(id, 64) {
            return Err(PublicationError::UnsafePath);
        }
        let count: i64 = self.connection.query_row(
            "SELECT (SELECT count(*) FROM verified_archives WHERE object_id = ?1) + (SELECT count(*) FROM verified_trees WHERE object_id = ?1)",
            [id], |row| row.get(0)).map_err(|_| PublicationError::Database)?;
        if count != 0 {
            return Err(PublicationError::Integrity);
        }
        let objects = private_dir(&self.root, "objects")?;
        let tree = matches!(kind, OrphanKind::Tree);
        let name = format!("{id}.{}", if tree { "tree" } else { "deb" });
        let fd = open_child(&objects, &name, tree)?;
        let device = fs::fstat(&objects)
            .map_err(|_| PublicationError::Io)?
            .st_dev;
        check_entry(&fd, tree, device)?;
        if tree {
            visit(&fd, device, 0, &mut 35_000, false)?;
            visit(&fd, device, 0, &mut 35_000, true)?;
        }
        fs::unlinkat(
            &objects,
            name.as_str(),
            if tree {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        )
        .map_err(|_| PublicationError::Io)?;
        fs::fsync(&objects).map_err(|_| PublicationError::Io)?;
        Ok(())
    }
}
