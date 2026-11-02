//! Protected per-source rollback floor. Artifact caching is not implemented yet.
use crate::{Distribution, Source, ValidatedRelease};
use rustix::{
    fs::{self, CWD, FileType, FlockOperation, Mode, OFlags},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    io::{Read, Write},
    os::fd::{AsFd, OwnedFd},
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, PartialEq, Eq)]
pub enum CacheError {
    UnsafePath,
    Busy,
    Io,
    Corrupt,
    Rollback,
    Equivocation,
    ClockRollback,
    Expired,
}
impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "snapshot journal failed: {self:?}")
    }
}
impl Error for CacheError {}

/// An open, protected local journal directory; callers must provide an existing directory.
#[derive(Debug)]
pub struct SnapshotJournal {
    directory: OwnedFd,
}
/// A freshly journaled snapshot; this is not a cached object or activation approval.
#[derive(Debug, Clone)]
pub struct SnapshotPin {
    release: ValidatedRelease,
}
impl SnapshotPin {
    pub fn release(&self) -> &ValidatedRelease {
        &self.release
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailurePoint {
    None,
    #[cfg(test)]
    BeforeRename,
    #[cfg(test)]
    AfterRename,
}

fn trusted(fd: &impl AsFd, kind: FileType, private_file: bool) -> Result<(), CacheError> {
    let stat = fs::fstat(fd).map_err(|_| CacheError::UnsafePath)?;
    if FileType::from_raw_mode(stat.st_mode) != kind
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || stat.st_mode & 0o022 != 0
        || (private_file
            && (stat.st_uid != geteuid().as_raw()
                || stat.st_mode & 0o077 != 0
                || stat.st_nlink != 1))
    {
        return Err(CacheError::UnsafePath);
    }
    Ok(())
}
impl SnapshotJournal {
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        let mut parts = path.components();
        if parts.next() != Some(Component::RootDir) {
            return Err(CacheError::UnsafePath);
        }
        if parts.clone().next().is_none() {
            return Err(CacheError::UnsafePath);
        }
        let mut current = fs::openat(
            CWD,
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CacheError::UnsafePath)?;
        trusted(&current, FileType::Directory, false)?;
        for part in parts {
            let Component::Normal(name) = part else {
                return Err(CacheError::UnsafePath);
            };
            current = fs::openat(
                &current,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| CacheError::UnsafePath)?;
            trusted(&current, FileType::Directory, false)?;
        }
        Ok(Self { directory: current })
    }

    /// Record the snapshot using the current system clock; failures never return a pin.
    pub fn record(&self, release: &ValidatedRelease) -> Result<SnapshotPin, CacheError> {
        self.record_at(release, SystemTime::now(), FailurePoint::None)
    }

    pub(crate) fn record_at(
        &self,
        release: &ValidatedRelease,
        now: SystemTime,
        failure: FailurePoint,
    ) -> Result<SnapshotPin, CacheError> {
        let now_seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CacheError::ClockRollback)?
            .as_secs();
        let name = source_key(release.source())?;
        let lock_name = format!("{name}.lock");
        let state_name = format!("{name}.state");
        let lock = fs::openat(
            &self.directory,
            lock_name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| CacheError::Io)?;
        trusted(&lock, FileType::RegularFile, true)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| CacheError::Busy)?;
        let digest: [u8; 32] = Sha256::digest(release.release().contents()).into();
        if let Some(previous) = read_state(&self.directory, &state_name)? {
            if now_seconds < previous.seen {
                return Err(CacheError::ClockRollback);
            }
            if release.signed_at() < previous.signed {
                return Err(CacheError::Rollback);
            }
            if release.signed_at() == previous.signed && digest != previous.digest {
                return Err(CacheError::Equivocation);
            }
        }
        if !release.is_valid_at(now) {
            return Err(CacheError::Expired);
        }
        let state = State {
            signed: release.signed_at(),
            seen: now_seconds,
            digest,
        };
        write_state(&self.directory, &state_name, &state, failure)?;
        Ok(SnapshotPin {
            release: release.clone(),
        })
    }
}

struct State {
    signed: u64,
    seen: u64,
    digest: [u8; 32],
}
pub(crate) fn source_key(source: &Source) -> Result<String, CacheError> {
    let mut hash = Sha256::new();
    fn field(hash: &mut Sha256, data: &str) {
        hash.update((data.len() as u64).to_be_bytes());
        hash.update(data.as_bytes());
    }
    field(&mut hash, "dich-source-policy-v1");
    field(
        &mut hash,
        match source.distribution() {
            Distribution::Debian => "debian",
            Distribution::Ubuntu => "ubuntu",
        },
    );
    let mut uri = url::Url::parse(source.uri()).map_err(|_| CacheError::UnsafePath)?;
    let canonical_path = uri.path().trim_end_matches('/').to_owned();
    uri.set_path(if canonical_path.is_empty() {
        "/"
    } else {
        &canonical_path
    });
    for value in [uri.as_str(), source.suite(), source.architecture()] {
        field(&mut hash, value);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
fn read_state(directory: &OwnedFd, name: &str) -> Result<Option<State>, CacheError> {
    let fd = match fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(CacheError::Io),
    };
    trusted(&fd, FileType::RegularFile, true)?;
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(57)
        .read_to_end(&mut bytes)
        .map_err(|_| CacheError::Io)?;
    if bytes.len() != 56 || &bytes[..8] != b"DICHFLO1" {
        return Err(CacheError::Corrupt);
    }
    let signed = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| CacheError::Corrupt)?);
    let seen = u64::from_be_bytes(bytes[16..24].try_into().map_err(|_| CacheError::Corrupt)?);
    let digest = bytes[24..56].try_into().map_err(|_| CacheError::Corrupt)?;
    Ok(Some(State {
        signed,
        seen,
        digest,
    }))
}
fn write_state(
    directory: &OwnedFd,
    name: &str,
    state: &State,
    failure: FailurePoint,
) -> Result<(), CacheError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| CacheError::Io)?;
    let temp = format!(
        ".stage-{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let fd = fs::openat(
        directory,
        temp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| CacheError::Io)?;
    let mut file = std::fs::File::from(fd);
    let result = (|| {
        file.write_all(b"DICHFLO1")
            .and_then(|_| file.write_all(&state.signed.to_be_bytes()))
            .and_then(|_| file.write_all(&state.seen.to_be_bytes()))
            .and_then(|_| file.write_all(&state.digest))
            .map_err(|_| CacheError::Io)?;
        file.sync_all().map_err(|_| CacheError::Io)?;
        #[cfg(test)]
        if failure == FailurePoint::BeforeRename {
            return Err(CacheError::Io);
        }
        let _ = failure;
        fs::renameat(directory, temp.as_str(), directory, name).map_err(|_| CacheError::Io)?;
        #[cfg(test)]
        if failure == FailurePoint::AfterRename {
            return Err(CacheError::Io);
        }
        fs::fsync(directory).map_err(|_| CacheError::Io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::unlinkat(directory, temp.as_str(), rustix::fs::AtFlags::empty());
    }
    result
}
