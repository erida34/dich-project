//! Durable publication of verified raw archives; no extraction or activation.
use crate::{MetadataDb, StoreIdentity, TransformPolicy};
use dich_apt::{AuthorizedArtifact, SnapshotJournal};
use rusqlite::{OptionalExtension, TransactionBehavior};
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::OwnedFd,
};

const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationOutcome {
    Published,
    Reused,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationError {
    Authentication,
    UnsafePath,
    Integrity,
    Collision,
    Limit,
    Io,
    Database,
    Injected,
}
impl fmt::Display for PublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "archive publication failed: {self:?}")
    }
}
impl Error for PublicationError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum FailurePoint {
    None,
    BeforeFileSync,
    AfterFileSync,
    AfterRename,
    AfterDirectorySync,
    BeforeCommit,
    AfterCommit,
}
pub(crate) fn fail(actual: FailurePoint, expected: FailurePoint) -> Result<(), PublicationError> {
    if actual == expected {
        #[cfg(test)]
        if std::env::var_os("DICH_INJECT_PROCESS_EXIT").is_some() {
            std::process::exit(86);
        }
        Err(PublicationError::Injected)
    } else {
        Ok(())
    }
}

impl MetadataDb {
    /// Publish only a reauthenticated cached raw archive. This does not publish a filesystem tree or activate a package.
    pub fn publish_cached_archive(
        &mut self,
        journal: &SnapshotJournal,
        authorized: &AuthorizedArtifact,
    ) -> Result<(StoreIdentity, PublicationOutcome), PublicationError> {
        let identity =
            StoreIdentity::from_cached(journal, authorized, TransformPolicy::VerifiedArchiveV1)
                .map_err(|_| PublicationError::Authentication)?;
        let artifact = journal
            .load_artifact(authorized)
            .map_err(|_| PublicationError::Authentication)?;
        let size = authorized.artifact().size();
        let digest = *authorized.artifact().sha256();
        let outcome = publish_reader(
            self,
            &identity,
            artifact,
            size,
            digest,
            FailurePoint::None,
            || {
                journal
                    .load_artifact(authorized)
                    .map(|_| ())
                    .map_err(|_| PublicationError::Authentication)
            },
        )?;
        Ok((identity, outcome))
    }
}
#[cfg(test)]
pub(crate) fn publish_for_test(
    db: &mut MetadataDb,
    identity: &StoreIdentity,
    reader: impl Read,
    size: u64,
    digest: [u8; 32],
    failure: FailurePoint,
) -> Result<PublicationOutcome, PublicationError> {
    publish_reader(db, identity, reader, size, digest, failure, || Ok(()))
}
pub(crate) fn publish_reader(
    db: &mut MetadataDb,
    identity: &StoreIdentity,
    mut input: impl Read,
    size: u64,
    expected: [u8; 32],
    failure: FailurePoint,
    revalidate: impl FnOnce() -> Result<(), PublicationError>,
) -> Result<PublicationOutcome, PublicationError> {
    if size == 0 || size > MAX_ARCHIVE {
        return Err(PublicationError::Limit);
    }
    let id = identity.hex();
    let row: Option<(Vec<u8>, i64, Vec<u8>)> = db.connection.query_row("SELECT manifest, artifact_size, artifact_sha256 FROM verified_archives WHERE object_id = ?1", [&id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional().map_err(|_| PublicationError::Database)?;
    if let Some((manifest, stored_size, stored_hash)) = &row {
        if manifest != &identity.canonical
            || *stored_size != size as i64
            || stored_hash.as_slice() != expected
        {
            return Err(PublicationError::Collision);
        }
    }
    let objects = private_dir(&db.root, "objects")?;
    let staging = private_dir(&db.root, "staging")?;
    let (name, fd) = create_stage(&staging)?;
    let mut guard = TempEntry {
        dir: &staging,
        name: Some(name.clone()),
    };
    let mut file = std::fs::File::from(fd);
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = input.read(&mut buf).map_err(|_| PublicationError::Io)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or(PublicationError::Limit)?;
        if count > size {
            return Err(PublicationError::Integrity);
        }
        hash.update(&buf[..n]);
        file.write_all(&buf[..n])
            .map_err(|_| PublicationError::Io)?;
    }
    if count != size || hash.finalize().as_slice() != expected {
        return Err(PublicationError::Integrity);
    }
    fail(failure, FailurePoint::BeforeFileSync)?;
    fs::fchmod(&file, Mode::from_raw_mode(0o400)).map_err(|_| PublicationError::Io)?;
    file.sync_all().map_err(|_| PublicationError::Io)?;
    fs::fsync(&staging).map_err(|_| PublicationError::Io)?;
    fail(failure, FailurePoint::AfterFileSync)?;
    let final_name = format!("{id}.deb");
    match open_existing(&objects, &final_name, size)? {
        Some(mut existing) => {
            file.seek(SeekFrom::Start(0))
                .map_err(|_| PublicationError::Io)?;
            compare_bytes(&mut existing, &mut file)?;
            existing.sync_all().map_err(|_| PublicationError::Io)?;
            if row.is_some() {
                revalidate()?;
                return Ok(PublicationOutcome::Reused);
            }
        }
        None => {
            if row.is_some() {
                return Err(PublicationError::Integrity);
            }
            fs::renameat_with(
                &staging,
                &name,
                &objects,
                &final_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| PublicationError::Io)?;
            guard.name = None;
            fail(failure, FailurePoint::AfterRename)?;
        }
    }
    // A retry may adopt a previously renamed orphan whose directory entry was never synced.
    fs::fsync(&objects).map_err(|_| PublicationError::Io)?;
    fs::fsync(&staging).map_err(|_| PublicationError::Io)?;
    fail(failure, FailurePoint::AfterDirectorySync)?;
    revalidate()?;
    let tx = db
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PublicationError::Database)?;
    tx.execute("INSERT INTO verified_archives (object_id, manifest, artifact_size, artifact_sha256) VALUES (?1, ?2, ?3, ?4)", rusqlite::params![id, identity.canonical, size as i64, expected.as_slice()]).map_err(|_| PublicationError::Database)?;
    fail(failure, FailurePoint::BeforeCommit)?;
    tx.commit().map_err(|_| PublicationError::Database)?;
    fail(failure, FailurePoint::AfterCommit)?;
    Ok(PublicationOutcome::Published)
}
pub(crate) fn private_dir(root: &OwnedFd, name: &str) -> Result<OwnedFd, PublicationError> {
    match fs::mkdirat(root, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => fs::fsync(root).map_err(|_| PublicationError::Io)?,
        Err(rustix::io::Errno::EXIST) => (),
        Err(_) => return Err(PublicationError::UnsafePath),
    }
    let fd = fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        fs::ResolveFlags::BENEATH
            | fs::ResolveFlags::NO_SYMLINKS
            | fs::ResolveFlags::NO_MAGICLINKS
            | fs::ResolveFlags::NO_XDEV,
    )
    .map_err(|_| PublicationError::UnsafePath)?;
    let stat = fs::fstat(&fd).map_err(|_| PublicationError::Io)?;
    let root_stat = fs::fstat(root).map_err(|_| PublicationError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || stat.st_mode & 0o077 != 0
        || stat.st_dev != root_stat.st_dev
    {
        return Err(PublicationError::UnsafePath);
    }
    Ok(fd)
}
fn create_stage(dir: &OwnedFd) -> Result<(String, OwnedFd), PublicationError> {
    for _ in 0..16 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| PublicationError::Io)?;
        let name = format!(
            "stage-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        match fs::openat(
            dir,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => return Ok((name, fd)),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(_) => return Err(PublicationError::Io),
        }
    }
    Err(PublicationError::Io)
}
struct TempEntry<'a> {
    dir: &'a OwnedFd,
    name: Option<String>,
}
impl Drop for TempEntry<'_> {
    fn drop(&mut self) {
        if let Some(name) = &self.name {
            let _ = fs::unlinkat(self.dir, name, AtFlags::empty());
        }
    }
}
fn open_existing(
    dir: &OwnedFd,
    name: &str,
    size: u64,
) -> Result<Option<std::fs::File>, PublicationError> {
    let fd = match fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(PublicationError::UnsafePath),
    };
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
    Ok(Some(std::fs::File::from(fd)))
}
fn compare_bytes(left: &mut impl Read, right: &mut impl Read) -> Result<(), PublicationError> {
    let mut a = [0u8; 65536];
    let mut b = [0u8; 65536];
    loop {
        let n = left.read(&mut a).map_err(|_| PublicationError::Io)?;
        let m = right.read(&mut b).map_err(|_| PublicationError::Io)?;
        if n != m || a[..n] != b[..m] {
            return Err(PublicationError::Integrity);
        }
        if n == 0 {
            return Ok(());
        }
    }
}
