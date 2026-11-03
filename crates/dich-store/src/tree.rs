//! Transactional publication of a conservative staged tree; never activation.
use crate::publication::{FailurePoint, PublicationError, fail, private_dir};
use crate::{MetadataDb, StoreIdentity, TransformPolicy};
use dich_apt::{AuthorizedArtifact, SnapshotJournal};
use dich_deb::{StagedArchive, StagedFile};
use rusqlite::{OptionalExtension, TransactionBehavior};
use rustix::{
    fs::{self, FileType, Mode, OFlags, RenameFlags, ResolveFlags},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    os::fd::OwnedFd,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeOutcome {
    Published,
    Reused,
}
pub(crate) trait TreeInput {
    fn directories(&self) -> &[String];
    fn files(&self) -> &[StagedFile];
    fn open(&self, path: &str) -> Result<Box<dyn Read>, PublicationError>;
}
impl TreeInput for StagedArchive {
    fn directories(&self) -> &[String] {
        self.directories()
    }
    fn files(&self) -> &[StagedFile] {
        self.files()
    }
    fn open(&self, path: &str) -> Result<Box<dyn Read>, PublicationError> {
        self.open_file(path)
            .map(|f| Box::new(f) as Box<dyn Read>)
            .map_err(|_| PublicationError::Integrity)
    }
}
impl MetadataDb {
    /// Publish a bound, verified staged tree. This never activates or executes package content.
    pub fn publish_cached_tree(
        &mut self,
        journal: &SnapshotJournal,
        authorized: &AuthorizedArtifact,
        stage: &StagedArchive,
    ) -> Result<(StoreIdentity, TreeOutcome), PublicationError> {
        if !stage.is_bound_to(authorized) {
            return Err(PublicationError::Authentication);
        }
        let identity =
            StoreIdentity::from_cached(journal, authorized, TransformPolicy::PrivateRegularFilesV1)
                .map_err(|_| PublicationError::Authentication)?;
        let result = publish_tree(self, &identity, stage, FailurePoint::None, || {
            journal
                .load_artifact(authorized)
                .map(|_| ())
                .map_err(|_| PublicationError::Authentication)
        })?;
        Ok((identity, result))
    }
}
#[cfg(test)]
pub(crate) fn publish_tree_for_test(
    db: &mut MetadataDb,
    identity: &StoreIdentity,
    stage: &impl TreeInput,
    failure: FailurePoint,
) -> Result<TreeOutcome, PublicationError> {
    publish_tree(db, identity, stage, failure, || Ok(()))
}
struct Manifest {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, (u64, [u8; 32])>,
    encoded: Vec<u8>,
    total: u64,
}
fn manifest(stage: &impl TreeInput) -> Result<Manifest, PublicationError> {
    if stage.directories().len() > 20_000 || stage.files().len() > 15_000 {
        return Err(PublicationError::Limit);
    }
    let mut dirs = BTreeSet::new();
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for dir in stage.directories() {
        if !safe_path(dir) || !dirs.insert(dir.clone()) {
            return Err(PublicationError::Integrity);
        }
    }
    for file in stage.files() {
        if !safe_path(&file.path) || file.size > 64 * 1024 * 1024 || dirs.contains(&file.path) {
            return Err(PublicationError::Integrity);
        }
        total = total
            .checked_add(file.size)
            .ok_or(PublicationError::Limit)?;
        if total > 128 * 1024 * 1024 {
            return Err(PublicationError::Limit);
        }
        let hash = parse_hash(&file.sha256)?;
        if files.insert(file.path.clone(), (file.size, hash)).is_some() {
            return Err(PublicationError::Integrity);
        }
    }
    for path in dirs.iter().chain(files.keys()) {
        for (i, byte) in path.bytes().enumerate() {
            if byte == b'/' && !dirs.contains(&path[..i]) {
                return Err(PublicationError::Integrity);
            }
        }
    }
    let mut encoded = b"dich.tree.manifest\0v1\0".to_vec();
    encoded.extend_from_slice(&(dirs.len() as u32).to_be_bytes());
    for dir in &dirs {
        encode_field(&mut encoded, dir.as_bytes());
    }
    encoded.extend_from_slice(&(files.len() as u32).to_be_bytes());
    for (path, (size, hash)) in &files {
        encode_field(&mut encoded, path.as_bytes());
        encoded.extend_from_slice(&size.to_be_bytes());
        encoded.extend_from_slice(hash);
    }
    Ok(Manifest {
        dirs,
        files,
        encoded,
        total,
    })
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.bytes().any(|b| b == b'\\' || b.is_ascii_control())
        && path.split('/').count() <= 128
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
fn encode_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}
fn parse_hash(hex: &str) -> Result<[u8; 32], PublicationError> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PublicationError::Integrity);
    }
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| PublicationError::Integrity)?;
    }
    Ok(result)
}
pub(crate) fn publish_tree(
    db: &mut MetadataDb,
    identity: &StoreIdentity,
    stage: &impl TreeInput,
    failure: FailurePoint,
    revalidate: impl FnOnce() -> Result<(), PublicationError>,
) -> Result<TreeOutcome, PublicationError> {
    let manifest = manifest(stage)?;
    let id = identity.hex();
    let row: Option<(Vec<u8>, Vec<u8>, i64)> = db
        .connection
        .query_row(
            "SELECT manifest, tree_manifest, total_size FROM verified_trees WHERE object_id = ?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| PublicationError::Database)?;
    if let Some((context, tree, size)) = &row {
        if context != &identity.canonical
            || tree != &manifest.encoded
            || *size != manifest.total as i64
        {
            return Err(PublicationError::Collision);
        }
    }
    let objects = private_dir(&db.root, "objects")?;
    let staging = private_dir(&db.root, "staging")?;
    let final_name = format!("{id}.tree");
    match open_dir_optional(&objects, &final_name)? {
        Some(root) => {
            verify_tree(&root, &manifest, true)?;
            sync_tree(&root, &manifest)?;
            if row.is_some() {
                revalidate()?;
                return Ok(TreeOutcome::Reused);
            }
        }
        None => {
            if row.is_some() {
                return Err(PublicationError::Integrity);
            }
            let (name, root) = create_tree_stage(&staging)?;
            copy_tree(&root, stage, &manifest, failure)?;
            verify_tree(&root, &manifest, true)?;
            sync_tree(&root, &manifest)?;
            fs::fsync(&staging).map_err(|_| PublicationError::Io)?;
            fail(failure, FailurePoint::AfterFileSync)?;
            fs::renameat_with(
                &staging,
                &name,
                &objects,
                &final_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| PublicationError::Io)?;
            fail(failure, FailurePoint::AfterRename)?;
        }
    }
    fs::fsync(&objects).map_err(|_| PublicationError::Io)?;
    fs::fsync(&staging).map_err(|_| PublicationError::Io)?;
    fail(failure, FailurePoint::AfterDirectorySync)?;
    revalidate()?;
    let tx = db
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PublicationError::Database)?;
    tx.execute("INSERT INTO verified_trees (object_id, manifest, tree_manifest, total_size) VALUES (?1, ?2, ?3, ?4)", rusqlite::params![id, identity.canonical, manifest.encoded, manifest.total as i64]).map_err(|_| PublicationError::Database)?;
    fail(failure, FailurePoint::BeforeCommit)?;
    tx.commit().map_err(|_| PublicationError::Database)?;
    fail(failure, FailurePoint::AfterCommit)?;
    Ok(TreeOutcome::Published)
}
fn resolve_flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}
fn open_dir(root: &OwnedFd, path: &str) -> Result<OwnedFd, PublicationError> {
    fs::openat2(
        root,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        resolve_flags(),
    )
    .map_err(|_| PublicationError::UnsafePath)
}
fn open_dir_optional(root: &OwnedFd, path: &str) -> Result<Option<OwnedFd>, PublicationError> {
    match fs::openat2(
        root,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        resolve_flags(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(PublicationError::UnsafePath),
    }
}
fn create_tree_stage(parent: &OwnedFd) -> Result<(String, OwnedFd), PublicationError> {
    for _ in 0..16 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| PublicationError::Io)?;
        let name = format!(
            "tree-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        match fs::mkdirat(parent, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => return Ok((name.clone(), open_dir(parent, &name)?)),
            Err(rustix::io::Errno::EXIST) => (),
            Err(_) => return Err(PublicationError::Io),
        }
    }
    Err(PublicationError::Io)
}
fn copy_tree(
    root: &OwnedFd,
    stage: &impl TreeInput,
    manifest: &Manifest,
    failure: FailurePoint,
) -> Result<(), PublicationError> {
    for dir in &manifest.dirs {
        let (parent, leaf) = dir.rsplit_once('/').unwrap_or((".", dir.as_str()));
        let parent_fd = open_dir(root, parent)?;
        fs::mkdirat(&parent_fd, leaf, Mode::from_raw_mode(0o700))
            .map_err(|_| PublicationError::UnsafePath)?;
        let _ = open_dir(root, dir)?;
    }
    for (path, (expected_size, expected_hash)) in &manifest.files {
        let fd = fs::openat2(
            root,
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            resolve_flags(),
        )
        .map_err(|_| PublicationError::UnsafePath)?;
        let mut output = std::fs::File::from(fd);
        let mut input = stage.open(path)?;
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut buf = [0u8; 65536];
        loop {
            let n = input.read(&mut buf).map_err(|_| PublicationError::Io)?;
            if n == 0 {
                break;
            }
            count = count.checked_add(n as u64).ok_or(PublicationError::Limit)?;
            if count > *expected_size {
                return Err(PublicationError::Integrity);
            }
            hash.update(&buf[..n]);
            output
                .write_all(&buf[..n])
                .map_err(|_| PublicationError::Io)?;
        }
        if count != *expected_size || hash.finalize().as_slice() != expected_hash {
            return Err(PublicationError::Integrity);
        }
        fail(failure, FailurePoint::BeforeFileSync)?;
        fs::fchmod(&output, Mode::from_raw_mode(0o400)).map_err(|_| PublicationError::Io)?;
        output.sync_all().map_err(|_| PublicationError::Io)?;
    }
    Ok(())
}
fn check_dir_mode(fd: &OwnedFd) -> Result<(), PublicationError> {
    let stat = fs::fstat(fd).map_err(|_| PublicationError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(PublicationError::Integrity);
    }
    Ok(())
}
fn verify_tree(
    root: &OwnedFd,
    manifest: &Manifest,
    sync_files: bool,
) -> Result<(), PublicationError> {
    check_dir_mode(root)?;
    let mut remaining_dirs = manifest.dirs.clone();
    let mut remaining_files = manifest.files.clone();
    let mut pending = vec![(String::new(), open_dir(root, ".")?)];
    while let Some((prefix, fd)) = pending.pop() {
        let mut reader = fs::Dir::read_from(&fd).map_err(|_| PublicationError::Io)?;
        while let Some(entry) = reader.read() {
            let entry = entry.map_err(|_| PublicationError::Io)?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| PublicationError::Integrity)?;
            if name == "." || name == ".." {
                continue;
            }
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if !safe_path(&path) {
                return Err(PublicationError::Integrity);
            }
            if remaining_dirs.remove(&path) {
                let child = open_dir(root, &path)?;
                check_dir_mode(&child)?;
                pending.push((path, child));
            } else if let Some((size, expected)) = remaining_files.remove(&path) {
                let fd = fs::openat2(
                    root,
                    path.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                    resolve_flags(),
                )
                .map_err(|_| PublicationError::UnsafePath)?;
                let stat = fs::fstat(&fd).map_err(|_| PublicationError::Io)?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                    || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
                    || stat.st_nlink != 1
                    || stat.st_mode & 0o7777 != 0o400
                    || stat.st_size < 0
                    || stat.st_size as u64 != size
                {
                    return Err(PublicationError::Integrity);
                }
                let mut file = std::fs::File::from(fd);
                let mut hash = Sha256::new();
                let mut buf = [0u8; 65536];
                let mut count = 0u64;
                loop {
                    let n = file.read(&mut buf).map_err(|_| PublicationError::Io)?;
                    if n == 0 {
                        break;
                    }
                    count = count.checked_add(n as u64).ok_or(PublicationError::Limit)?;
                    if count > size {
                        return Err(PublicationError::Integrity);
                    }
                    hash.update(&buf[..n]);
                }
                if count != size || hash.finalize().as_slice() != expected {
                    return Err(PublicationError::Integrity);
                }
                if sync_files {
                    file.sync_all().map_err(|_| PublicationError::Io)?;
                }
            } else {
                return Err(PublicationError::Integrity);
            }
        }
    }
    if !remaining_dirs.is_empty() || !remaining_files.is_empty() {
        return Err(PublicationError::Integrity);
    }
    Ok(())
}
fn sync_tree(root: &OwnedFd, manifest: &Manifest) -> Result<(), PublicationError> {
    let mut dirs: Vec<_> = manifest.dirs.iter().collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.split('/').count()));
    for path in dirs {
        fs::fsync(open_dir(root, path)?).map_err(|_| PublicationError::Io)?;
    }
    fs::fsync(root).map_err(|_| PublicationError::Io)
}

/// Verification against locally recorded metadata, not repository freshness or compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeVerification {
    pub files: usize,
    pub directories: usize,
    pub total_bytes: u64,
}
struct ManifestInput {
    dirs: Vec<String>,
    files: Vec<StagedFile>,
}
impl TreeInput for ManifestInput {
    fn directories(&self) -> &[String] {
        &self.dirs
    }
    fn files(&self) -> &[StagedFile] {
        &self.files
    }
    fn open(&self, _path: &str) -> Result<Box<dyn Read>, PublicationError> {
        Err(PublicationError::Integrity)
    }
}
fn decode_manifest(bytes: &[u8]) -> Result<Manifest, PublicationError> {
    const PREFIX: &[u8] = b"dich.tree.manifest\0v1\0";
    if bytes.len() > 64 * 1024 * 1024 || !bytes.starts_with(PREFIX) {
        return Err(PublicationError::Integrity);
    }
    let mut cursor = std::io::Cursor::new(&bytes[PREFIX.len()..]);
    fn read_u32(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u32, PublicationError> {
        let mut b = [0; 4];
        cursor
            .read_exact(&mut b)
            .map_err(|_| PublicationError::Integrity)?;
        Ok(u32::from_be_bytes(b))
    }
    fn read_path(cursor: &mut std::io::Cursor<&[u8]>) -> Result<String, PublicationError> {
        let n = read_u32(cursor)? as usize;
        if n == 0 || n > 4096 {
            return Err(PublicationError::Integrity);
        }
        let mut b = vec![0; n];
        cursor
            .read_exact(&mut b)
            .map_err(|_| PublicationError::Integrity)?;
        String::from_utf8(b).map_err(|_| PublicationError::Integrity)
    }
    let ndirs = read_u32(&mut cursor)? as usize;
    if ndirs > 20_000 {
        return Err(PublicationError::Limit);
    }
    let mut dirs = Vec::with_capacity(ndirs);
    for _ in 0..ndirs {
        dirs.push(read_path(&mut cursor)?);
    }
    let nfiles = read_u32(&mut cursor)? as usize;
    if nfiles > 15_000 {
        return Err(PublicationError::Limit);
    }
    let mut files = Vec::with_capacity(nfiles);
    for _ in 0..nfiles {
        let path = read_path(&mut cursor)?;
        let mut size = [0; 8];
        let mut digest = [0; 32];
        cursor
            .read_exact(&mut size)
            .map_err(|_| PublicationError::Integrity)?;
        cursor
            .read_exact(&mut digest)
            .map_err(|_| PublicationError::Integrity)?;
        files.push(StagedFile {
            path,
            size: u64::from_be_bytes(size),
            sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
        });
    }
    if cursor.position() != (bytes.len() - PREFIX.len()) as u64 {
        return Err(PublicationError::Integrity);
    }
    let result = manifest(&ManifestInput { dirs, files })?;
    if result.encoded != bytes {
        return Err(PublicationError::Integrity);
    }
    Ok(result)
}
impl MetadataDb {
    /// Verify a committed private tree against local metadata. Does not reauthenticate a repository.
    pub fn verify_tree_object(&self, id: &str) -> Result<TreeVerification, PublicationError> {
        let (context, tree, size): (Vec<u8>, Vec<u8>, i64) = self.connection.query_row(
            "SELECT manifest, tree_manifest, total_size FROM verified_trees WHERE object_id = ?1", [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))
        ).map_err(|_| PublicationError::Integrity)?;
        crate::verify_identity_context(id, &context, 1)?;
        let manifest = decode_manifest(&tree)?;
        if size < 0 || size as u64 != manifest.total {
            return Err(PublicationError::Integrity);
        }
        let objects = crate::publication::open_private_dir(&self.root, "objects")?;
        let root = open_dir_optional(&objects, &format!("{id}.tree"))?
            .ok_or(PublicationError::Integrity)?;
        verify_tree(&root, &manifest, false)?;
        Ok(TreeVerification {
            files: manifest.files.len(),
            directories: manifest.dirs.len(),
            total_bytes: manifest.total,
        })
    }
}
