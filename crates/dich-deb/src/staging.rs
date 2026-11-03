//! Private staging, never publication or package activation.
use crate::{DebError, Limits, decompress, inspect_deb, normalize_path, preflight_ar};
use dich_apt::{AuthorizedArtifact, SnapshotJournal};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use std::{
    error::Error,
    fmt,
    io::{Cursor, Read},
    path::Path,
    time::SystemTime,
};

#[derive(Debug)]
pub enum StageError {
    Authentication,
    Archive(DebError),
    Filesystem,
}
impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "private staging failed: {self:?}")
    }
}
impl Error for StageError {}
/// Temporary, private files only; dropping this object removes the staging tree best-effort.
pub struct StagedArchive {
    _directory: tempfile::TempDir,
    root: std::os::fd::OwnedFd,
}
impl StagedArchive {
    /// Read a regular staged file without resolving a host path or following links.
    pub fn open_file(&self, path: &str) -> Result<std::fs::File, StageError> {
        let normalized = normalize_path(path.as_bytes(), false).map_err(StageError::Archive)?;
        let name = std::str::from_utf8(&normalized).map_err(|_| StageError::Filesystem)?;
        let fd = fs::openat2(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| StageError::Filesystem)?;
        let stat = fs::fstat(&fd).map_err(|_| StageError::Filesystem)?;
        if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
            || stat.st_nlink != 1
        {
            return Err(StageError::Filesystem);
        }
        Ok(std::fs::File::from(fd))
    }
}

/// Stage a cached artifact only after the journal rechecks its signed authorization and hash.
pub fn stage_cached(
    journal: &SnapshotJournal,
    authorized: &AuthorizedArtifact,
    limits: Limits,
) -> Result<StagedArchive, StageError> {
    if limits.max_archive_bytes == 0 || limits.max_archive_bytes > 256 * 1024 * 1024 {
        return Err(StageError::Archive(DebError::Limit));
    }
    if authorized.artifact().size() > limits.max_archive_bytes as u64
        || !authorized.is_valid_at(SystemTime::now())
    {
        return Err(StageError::Authentication);
    }
    let mut artifact = journal
        .load_artifact(authorized)
        .map_err(|_| StageError::Authentication)?;
    let mut bytes = Vec::new();
    artifact
        .by_ref()
        .take(limits.max_archive_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StageError::Authentication)?;
    if bytes.len() > limits.max_archive_bytes {
        return Err(StageError::Archive(DebError::Limit));
    }
    let stage = stage_untrusted(&bytes, limits)?;
    if !authorized.is_valid_at(SystemTime::now()) {
        return Err(StageError::Authentication);
    }
    journal
        .load_artifact(authorized)
        .map_err(|_| StageError::Authentication)?;
    Ok(stage)
}

#[cfg(test)]
pub(crate) fn stage_untrusted_for_test(
    bytes: &[u8],
    limits: Limits,
) -> Result<StagedArchive, StageError> {
    stage_untrusted(bytes, limits)
}
fn stage_untrusted(bytes: &[u8], limits: Limits) -> Result<StagedArchive, StageError> {
    stage_with_hook(bytes, limits, |_| {})
}
fn stage_with_hook(
    bytes: &[u8],
    limits: Limits,
    hook: impl FnOnce(&Path),
) -> Result<StagedArchive, StageError> {
    inspect_deb(bytes, limits).map_err(StageError::Archive)?;
    let formats = preflight_ar(bytes).map_err(StageError::Archive)?;
    let mut archive = ar::Archive::new(Cursor::new(bytes));
    let mut data = None;
    for index in 0..3 {
        let mut member = archive
            .next_entry()
            .ok_or(StageError::Filesystem)?
            .map_err(|_| StageError::Filesystem)?;
        if index == 2 {
            let mut body = Vec::new();
            member
                .read_to_end(&mut body)
                .map_err(|_| StageError::Filesystem)?;
            data = Some(body);
        }
    }
    let data = decompress(
        formats[1],
        &data.ok_or(StageError::Filesystem)?,
        limits.max_expanded_tar_bytes,
    )
    .map_err(StageError::Archive)?;
    let tmp = fs::open(
        "/tmp",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StageError::Filesystem)?;
    let stat = fs::fstat(&tmp).map_err(|_| StageError::Filesystem)?;
    if stat.st_uid != 0 || (stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0) {
        return Err(StageError::Filesystem);
    }
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .prefix("dich-stage-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| StageError::Filesystem)?;
    let leaf = directory.path().file_name().ok_or(StageError::Filesystem)?;
    let root = fs::openat(
        &tmp,
        leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StageError::Filesystem)?;
    let stage_stat = fs::fstat(&root).map_err(|_| StageError::Filesystem)?;
    if stage_stat.st_uid != rustix::process::geteuid().as_raw() || stage_stat.st_mode & 0o077 != 0 {
        return Err(StageError::Filesystem);
    }
    hook(directory.path());
    check_attached(&tmp, leaf, &stage_stat)?;
    let mut archive = tar::Archive::new(Cursor::new(&data));
    for entry in archive
        .entries()
        .map_err(|_| StageError::Filesystem)?
        .raw(true)
    {
        let mut entry = entry.map_err(|_| StageError::Filesystem)?;
        let directory_entry = entry.header().entry_type().is_dir();
        let normalized =
            normalize_path(&entry.path_bytes(), directory_entry).map_err(StageError::Archive)?;
        if normalized.is_empty() {
            continue;
        }
        let name = std::str::from_utf8(&normalized).map_err(|_| StageError::Filesystem)?;
        let parts: Vec<&str> = name.split('/').collect();
        let parent_count = if directory_entry {
            parts.len()
        } else {
            parts.len() - 1
        };
        let mut relative = String::new();
        for part in &parts[..parent_count] {
            let parent = if relative.is_empty() { "." } else { &relative };
            let parent_fd = open_directory(&root, parent)?;
            match fs::mkdirat(&parent_fd, *part, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => (),
                Err(_) => return Err(StageError::Filesystem),
            }
            if !relative.is_empty() {
                relative.push('/');
            }
            relative.push_str(part);
            let _ = open_directory(&root, &relative)?;
        }
        if !directory_entry {
            let fd = fs::openat2(
                &root,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )
            .map_err(|_| StageError::Filesystem)?;
            let mut file = std::fs::File::from(fd);
            let copied =
                std::io::copy(&mut entry, &mut file).map_err(|_| StageError::Filesystem)?;
            if copied != entry.size() {
                return Err(StageError::Filesystem);
            }
        }
    }
    check_attached(&tmp, leaf, &stage_stat)?;
    Ok(StagedArchive {
        _directory: directory,
        root,
    })
}
fn check_attached(
    parent: &impl std::os::fd::AsFd,
    name: &std::ffi::OsStr,
    original: &rustix::fs::Stat,
) -> Result<(), StageError> {
    let fd = fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StageError::Filesystem)?;
    let stat = fs::fstat(&fd).map_err(|_| StageError::Filesystem)?;
    if stat.st_dev != original.st_dev || stat.st_ino != original.st_ino {
        return Err(StageError::Filesystem);
    }
    Ok(())
}
fn open_directory(
    root: &impl std::os::fd::AsFd,
    path: &str,
) -> Result<std::os::fd::OwnedFd, StageError> {
    fs::openat2(
        root,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| StageError::Filesystem)
}

#[cfg(test)]
pub(crate) fn stage_with_test_hook(
    bytes: &[u8],
    limits: Limits,
    hook: impl FnOnce(&Path),
) -> Result<StagedArchive, StageError> {
    stage_with_hook(bytes, limits, hook)
}
