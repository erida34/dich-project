//! Protected per-source rollback floor and verified temporary artifact cache.
use crate::artifact::verify_artifact_stream_with_clock;
use crate::signatures::SignedEnvelope;
use crate::{
    AuthorizedArtifact, Distribution, FreshnessPolicy, IndexFormat, IndexLimits, Source,
    ValidatedRelease, VerifiedArtifact, VerifiedIndex, validate_release,
    verify_configured_detached_release, verify_configured_inrelease,
    verify_packages_index_with_limits,
};
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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    NotFound,
    Integrity,
    Authentication,
    Fetch(crate::FetchError),
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
    #[cfg(test)]
    ArtifactBeforeRename,
    #[cfg(test)]
    ArtifactAfterRename,
    #[cfg(test)]
    ReleaseBeforeRename,
    #[cfg(test)]
    ReleaseAfterRename,
    #[cfg(test)]
    IndexBeforeRename,
    #[cfg(test)]
    IndexAfterRename,
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

    /// Download under the source lock and rollback floor, verifying TLS, size and SHA256.
    pub fn fetch_artifact(
        &self,
        authorized: &AuthorizedArtifact,
        max_bytes: u64,
    ) -> Result<VerifiedArtifact, CacheError> {
        let mut transport = crate::transport::HttpsTransport::new();
        self.fetch_with_transport(authorized, max_bytes, &mut transport, SystemTime::now)
    }

    pub(crate) fn fetch_with_transport(
        &self,
        authorized: &AuthorizedArtifact,
        max_bytes: u64,
        transport: &mut impl crate::transport::Transport,
        clock: impl Fn() -> SystemTime,
    ) -> Result<VerifiedArtifact, CacheError> {
        let (_, _guard) =
            self.lock_and_record(authorized.release(), clock(), FailurePoint::None)?;
        let verified =
            crate::transport::fetch_with_transport(authorized, max_bytes, transport, &clock)
                .map_err(CacheError::Fetch)?;
        self.record_locked(authorized.release(), clock(), FailurePoint::None)?;
        Ok(verified)
    }

    pub(crate) fn record_at(
        &self,
        release: &ValidatedRelease,
        now: SystemTime,
        failure: FailurePoint,
    ) -> Result<SnapshotPin, CacheError> {
        let (pin, _guard) = self.lock_and_record(release, now, failure)?;
        Ok(pin)
    }

    fn lock_and_record(
        &self,
        release: &ValidatedRelease,
        now: SystemTime,
        failure: FailurePoint,
    ) -> Result<(SnapshotPin, OwnedFd), CacheError> {
        let lock = self.lock_source(release.source())?;
        reverify_release(release, now)?;
        self.record_locked(release, now, failure)?;
        Ok((
            SnapshotPin {
                release: release.clone(),
            },
            lock,
        ))
    }

    fn lock_source(&self, source: &Source) -> Result<OwnedFd, CacheError> {
        let name = source_key(source)?;
        let lock_name = format!("{name}.lock");
        let lock = fs::openat(
            &self.directory,
            lock_name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| CacheError::Io)?;
        trusted(&lock, FileType::RegularFile, true)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::AGAIN) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(rustix::io::Errno::AGAIN) => return Err(CacheError::Busy),
                Err(_) => return Err(CacheError::Io),
            }
        }
        Ok(lock)
    }

    fn record_locked(
        &self,
        release: &ValidatedRelease,
        now: SystemTime,
        failure: FailurePoint,
    ) -> Result<(), CacheError> {
        let now_seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CacheError::ClockRollback)?
            .as_secs();
        let name = source_key(release.source())?;
        let state_name = format!("{name}.state");
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
        Ok(())
    }

    /// Publish a previously verified artifact atomically. This does not cache its Release/index.
    pub fn store_artifact(
        &self,
        authorized: &AuthorizedArtifact,
        verified: VerifiedArtifact,
    ) -> Result<(), CacheError> {
        self.store_artifact_with_clock(authorized, verified, FailurePoint::None, SystemTime::now)
    }

    /// Read a cached artifact only after rechecking the source floor, freshness and digest.
    pub fn load_artifact(
        &self,
        authorized: &AuthorizedArtifact,
    ) -> Result<VerifiedArtifact, CacheError> {
        self.load_artifact_with_clock(authorized, SystemTime::now)
    }

    /// Store the original signed Release envelope for later re-verification.
    pub fn store_release(&self, release: &ValidatedRelease) -> Result<(), CacheError> {
        self.store_release_with_clock(release, FailurePoint::None, SystemTime::now)
    }

    /// Reload the current source snapshot, rechecking its signature and time policy.
    pub fn load_release(
        &self,
        source: &Source,
        policy: FreshnessPolicy,
    ) -> Result<ValidatedRelease, CacheError> {
        self.load_release_with_clock(source, policy, SystemTime::now)
    }

    /// Verify and cache one compressed Packages index under the signed Release.
    pub fn store_index(
        &self,
        release: &ValidatedRelease,
        component: &str,
        format: IndexFormat,
        bytes: &[u8],
        limits: IndexLimits,
    ) -> Result<(), CacheError> {
        self.store_index_with_clock(
            release,
            component,
            format,
            bytes,
            limits,
            FailurePoint::None,
            SystemTime::now,
        )
    }

    /// Reload a Release and its index after reauthenticating metadata and rechecking the index hash.
    pub fn load_index(
        &self,
        source: &Source,
        policy: FreshnessPolicy,
        component: &str,
        format: IndexFormat,
        limits: IndexLimits,
    ) -> Result<(ValidatedRelease, VerifiedIndex), CacheError> {
        self.load_index_with_clock(source, policy, component, format, limits, SystemTime::now)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_index_at(
        &self,
        release: &ValidatedRelease,
        component: &str,
        format: IndexFormat,
        bytes: &[u8],
        limits: IndexLimits,
        now: SystemTime,
        failure: FailurePoint,
    ) -> Result<(), CacheError> {
        self.store_index_with_clock(release, component, format, bytes, limits, failure, || now)
    }
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn load_index_at(
        &self,
        source: &Source,
        policy: FreshnessPolicy,
        component: &str,
        format: IndexFormat,
        limits: IndexLimits,
        now: SystemTime,
    ) -> Result<(ValidatedRelease, VerifiedIndex), CacheError> {
        self.load_index_with_clock(source, policy, component, format, limits, || now)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_index_with_clock(
        &self,
        release: &ValidatedRelease,
        component: &str,
        format: IndexFormat,
        bytes: &[u8],
        limits: IndexLimits,
        failure: FailurePoint,
        clock: impl Fn() -> SystemTime,
    ) -> Result<(), CacheError> {
        let (_, _guard) = self.lock_and_record(release, clock(), FailurePoint::None)?;
        verify_packages_index_with_limits(release.release(), component, format, bytes, limits)
            .map_err(|_| CacheError::Integrity)?;
        let name = index_name(
            release.source(),
            release.release().contents(),
            component,
            format,
        )?;
        let temp = stage_name()?;
        let fd = fs::openat(
            &self.directory,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| CacheError::Io)?;
        let mut file = std::fs::File::from(fd);
        let result = (|| {
            file.write_all(bytes).map_err(|_| CacheError::Io)?;
            file.sync_all().map_err(|_| CacheError::Io)?;
            self.record_locked(release, clock(), FailurePoint::None)?;
            #[cfg(test)]
            if failure == FailurePoint::IndexBeforeRename {
                return Err(CacheError::Io);
            }
            let _ = failure;
            fs::renameat(
                &self.directory,
                temp.as_str(),
                &self.directory,
                name.as_str(),
            )
            .map_err(|_| CacheError::Io)?;
            #[cfg(test)]
            if failure == FailurePoint::IndexAfterRename {
                return Err(CacheError::Io);
            }
            fs::fsync(&self.directory).map_err(|_| CacheError::Io)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.directory, temp.as_str(), rustix::fs::AtFlags::empty());
        }
        result
    }

    pub(crate) fn load_index_with_clock(
        &self,
        source: &Source,
        policy: FreshnessPolicy,
        component: &str,
        format: IndexFormat,
        limits: IndexLimits,
        clock: impl Fn() -> SystemTime,
    ) -> Result<(ValidatedRelease, VerifiedIndex), CacheError> {
        let _guard = self.lock_source(source)?;
        let release = self.load_release_locked(source, policy, &clock)?;
        let name = index_name(source, release.release().contents(), component, format)?;
        let fd = fs::openat(
            &self.directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == rustix::io::Errno::NOENT {
                CacheError::NotFound
            } else {
                CacheError::Io
            }
        })?;
        trusted(&fd, FileType::RegularFile, true)?;
        let mut bytes = Vec::new();
        std::fs::File::from(fd)
            .take((limits.compressed_limit() + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| CacheError::Io)?;
        if bytes.len() > limits.compressed_limit() {
            return Err(CacheError::Integrity);
        }
        let index =
            verify_packages_index_with_limits(release.release(), component, format, &bytes, limits)
                .map_err(|_| CacheError::Integrity)?;
        self.record_locked(&release, clock(), FailurePoint::None)?;
        Ok((release, index))
    }

    #[cfg(test)]
    pub(crate) fn store_release_at(
        &self,
        release: &ValidatedRelease,
        now: SystemTime,
        failure: FailurePoint,
    ) -> Result<(), CacheError> {
        self.store_release_with_clock(release, failure, || now)
    }
    #[cfg(test)]
    pub(crate) fn load_release_at(
        &self,
        source: &Source,
        policy: FreshnessPolicy,
        now: SystemTime,
    ) -> Result<ValidatedRelease, CacheError> {
        self.load_release_with_clock(source, policy, || now)
    }

    pub(crate) fn store_release_with_clock(
        &self,
        release: &ValidatedRelease,
        failure: FailurePoint,
        clock: impl Fn() -> SystemTime,
    ) -> Result<(), CacheError> {
        let (_, _guard) = self.lock_and_record(release, clock(), FailurePoint::None)?;
        let name = release_name(release.source(), release.release().contents())?;
        let temp = stage_name()?;
        let fd = fs::openat(
            &self.directory,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| CacheError::Io)?;
        let mut file = std::fs::File::from(fd);
        let result = (|| {
            file.write_all(b"DICHREL1").map_err(|_| CacheError::Io)?;
            match &release.release().envelope {
                SignedEnvelope::Inline(input) => {
                    file.write_all(&[0])
                        .and_then(|_| file.write_all(&(input.len() as u32).to_be_bytes()))
                        .and_then(|_| file.write_all(input))
                        .map_err(|_| CacheError::Io)?;
                }
                SignedEnvelope::Detached { release, signature } => {
                    file.write_all(&[1])
                        .and_then(|_| file.write_all(&(release.len() as u32).to_be_bytes()))
                        .and_then(|_| file.write_all(&(signature.len() as u32).to_be_bytes()))
                        .and_then(|_| file.write_all(release))
                        .and_then(|_| file.write_all(signature))
                        .map_err(|_| CacheError::Io)?;
                }
            }
            file.sync_all().map_err(|_| CacheError::Io)?;
            self.record_locked(release, clock(), FailurePoint::None)?;
            #[cfg(test)]
            if failure == FailurePoint::ReleaseBeforeRename {
                return Err(CacheError::Io);
            }
            let _ = failure;
            fs::renameat(
                &self.directory,
                temp.as_str(),
                &self.directory,
                name.as_str(),
            )
            .map_err(|_| CacheError::Io)?;
            #[cfg(test)]
            if failure == FailurePoint::ReleaseAfterRename {
                return Err(CacheError::Io);
            }
            fs::fsync(&self.directory).map_err(|_| CacheError::Io)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.directory, temp.as_str(), rustix::fs::AtFlags::empty());
        }
        result
    }

    pub(crate) fn load_release_with_clock(
        &self,
        source: &Source,
        policy: FreshnessPolicy,
        clock: impl Fn() -> SystemTime,
    ) -> Result<ValidatedRelease, CacheError> {
        let _guard = self.lock_source(source)?;
        self.load_release_locked(source, policy, &clock)
    }

    fn load_release_locked(
        &self,
        source: &Source,
        policy: FreshnessPolicy,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<ValidatedRelease, CacheError> {
        let key = source_key(source)?;
        let state =
            read_state(&self.directory, &format!("{key}.state"))?.ok_or(CacheError::NotFound)?;
        let now = clock();
        let now_seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CacheError::ClockRollback)?
            .as_secs();
        if now_seconds < state.seen {
            return Err(CacheError::ClockRollback);
        }
        let name = release_name_from_digest(&key, &state.digest);
        let fd = fs::openat(
            &self.directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == rustix::io::Errno::NOENT {
                CacheError::NotFound
            } else {
                CacheError::Io
            }
        })?;
        trusted(&fd, FileType::RegularFile, true)?;
        let mut bytes = Vec::new();
        std::fs::File::from(fd)
            .take(5 * 1024 * 1024 + 32)
            .read_to_end(&mut bytes)
            .map_err(|_| CacheError::Io)?;
        let envelope = decode_envelope(&bytes)?;
        let verified = match envelope {
            SignedEnvelope::Inline(input) => verify_configured_inrelease(source, &input),
            SignedEnvelope::Detached { release, signature } => {
                verify_configured_detached_release(source, &release, &signature)
            }
        }
        .map_err(|_| CacheError::Authentication)?;
        let digest: [u8; 32] = Sha256::digest(verified.contents()).into();
        if digest != state.digest {
            return Err(CacheError::Integrity);
        }
        let validated =
            validate_release(&verified, clock(), policy).map_err(|_| CacheError::Authentication)?;
        if validated.signed_at() != state.signed {
            return Err(CacheError::Integrity);
        }
        self.record_locked(&validated, clock(), FailurePoint::None)?;
        Ok(validated)
    }

    #[cfg(test)]
    pub(crate) fn store_artifact_at(
        &self,
        authorized: &AuthorizedArtifact,
        verified: VerifiedArtifact,
        now: SystemTime,
        failure: FailurePoint,
    ) -> Result<(), CacheError> {
        self.store_artifact_with_clock(authorized, verified, failure, || now)
    }
    #[cfg(test)]
    pub(crate) fn load_artifact_at(
        &self,
        authorized: &AuthorizedArtifact,
        now: SystemTime,
    ) -> Result<VerifiedArtifact, CacheError> {
        self.load_artifact_with_clock(authorized, || now)
    }

    fn store_artifact_with_clock(
        &self,
        authorized: &AuthorizedArtifact,
        mut verified: VerifiedArtifact,
        failure: FailurePoint,
        clock: impl Fn() -> SystemTime,
    ) -> Result<(), CacheError> {
        if verified.metadata() != authorized.artifact() {
            return Err(CacheError::Integrity);
        }
        let (_, _guard) =
            self.lock_and_record(authorized.release(), clock(), FailurePoint::None)?;
        verified.rewind().map_err(|_| CacheError::Io)?;
        let name = blob_name(authorized);
        let temp = stage_name()?;
        let fd = fs::openat(
            &self.directory,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| CacheError::Io)?;
        let mut file = std::fs::File::from(fd);
        let result = (|| {
            let mut hash = Sha256::new();
            let mut count = 0u64;
            let mut buffer = [0u8; 65536];
            loop {
                let n = verified.read(&mut buffer).map_err(|_| CacheError::Io)?;
                if n == 0 {
                    break;
                }
                count = count.checked_add(n as u64).ok_or(CacheError::Integrity)?;
                if count > authorized.artifact().size() {
                    return Err(CacheError::Integrity);
                }
                hash.update(&buffer[..n]);
                file.write_all(&buffer[..n]).map_err(|_| CacheError::Io)?;
            }
            let digest: [u8; 32] = hash.finalize().into();
            if count != authorized.artifact().size() || &digest != authorized.artifact().sha256() {
                return Err(CacheError::Integrity);
            }
            file.sync_all().map_err(|_| CacheError::Io)?;
            self.record_locked(authorized.release(), clock(), FailurePoint::None)?;
            #[cfg(test)]
            if failure == FailurePoint::ArtifactBeforeRename {
                return Err(CacheError::Io);
            }
            let _ = failure;
            match fs::renameat_with(
                &self.directory,
                temp.as_str(),
                &self.directory,
                name.as_str(),
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => (),
                Err(rustix::io::Errno::EXIST) => {
                    self.read_blob(authorized, &clock)?;
                    fs::unlinkat(&self.directory, temp.as_str(), rustix::fs::AtFlags::empty())
                        .map_err(|_| CacheError::Io)?;
                }
                Err(_) => return Err(CacheError::Io),
            }
            #[cfg(test)]
            if failure == FailurePoint::ArtifactAfterRename {
                return Err(CacheError::Io);
            }
            fs::fsync(&self.directory).map_err(|_| CacheError::Io)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.directory, temp.as_str(), rustix::fs::AtFlags::empty());
        }
        result
    }

    fn load_artifact_with_clock(
        &self,
        authorized: &AuthorizedArtifact,
        clock: impl Fn() -> SystemTime,
    ) -> Result<VerifiedArtifact, CacheError> {
        let (_, _guard) =
            self.lock_and_record(authorized.release(), clock(), FailurePoint::None)?;
        let result = self.read_blob(authorized, &clock)?;
        self.record_locked(authorized.release(), clock(), FailurePoint::None)?;
        Ok(result)
    }

    fn read_blob(
        &self,
        authorized: &AuthorizedArtifact,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<VerifiedArtifact, CacheError> {
        let name = blob_name(authorized);
        let fd = fs::openat(
            &self.directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == rustix::io::Errno::NOENT {
                CacheError::NotFound
            } else {
                CacheError::Io
            }
        })?;
        trusted(&fd, FileType::RegularFile, true)?;
        let stat = fs::fstat(&fd).map_err(|_| CacheError::Io)?;
        if stat.st_size < 0 || stat.st_size as u64 != authorized.artifact().size() {
            return Err(CacheError::Integrity);
        }
        verify_artifact_stream_with_clock(
            authorized,
            std::fs::File::from(fd),
            authorized.artifact().size(),
            clock,
        )
        .map_err(|_| CacheError::Integrity)
    }
}

fn reverify_release(release: &ValidatedRelease, now: SystemTime) -> Result<(), CacheError> {
    let source = release.source();
    let verified = match &release.release().envelope {
        SignedEnvelope::Inline(input) => verify_configured_inrelease(source, input),
        SignedEnvelope::Detached { release, signature } => {
            verify_configured_detached_release(source, release, signature)
        }
    }
    .map_err(|_| CacheError::Authentication)?;
    if verified.contents() != release.release().contents() {
        return Err(CacheError::Integrity);
    }
    validate_release(&verified, now, release.policy()).map_err(|_| CacheError::Authentication)?;
    Ok(())
}

fn blob_name(authorized: &AuthorizedArtifact) -> String {
    format!(
        "blob-{}",
        authorized
            .artifact()
            .sha256()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

pub(crate) fn release_name(source: &Source, contents: &[u8]) -> Result<String, CacheError> {
    let digest: [u8; 32] = Sha256::digest(contents).into();
    Ok(release_name_from_digest(&source_key(source)?, &digest))
}
fn release_name_from_digest(source: &str, digest: &[u8; 32]) -> String {
    format!(
        "release-{source}-{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
pub(crate) fn index_name(
    source: &Source,
    release: &[u8],
    component: &str,
    format: IndexFormat,
) -> Result<String, CacheError> {
    if !source.components().iter().any(|value| value == component) {
        return Err(CacheError::Integrity);
    }
    let digest = Sha256::digest(release);
    let mut index_key = Sha256::new();
    index_key.update((component.len() as u64).to_be_bytes());
    index_key.update(component.as_bytes());
    index_key.update(match format {
        IndexFormat::Gzip => b"gz".as_slice(),
        IndexFormat::Xz => b"xz".as_slice(),
    });
    Ok(format!(
        "index-{}-{}-{}",
        source_key(source)?,
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        index_key
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
fn decode_envelope(bytes: &[u8]) -> Result<SignedEnvelope, CacheError> {
    if bytes.len() < 13 || bytes.get(..8) != Some(b"DICHREL1") {
        return Err(CacheError::Corrupt);
    }
    let mode = bytes[8];
    let first =
        u32::from_be_bytes(bytes[9..13].try_into().map_err(|_| CacheError::Corrupt)?) as usize;
    if first == 0 || first > 4 * 1024 * 1024 {
        return Err(CacheError::Corrupt);
    }
    match mode {
        0 if bytes.len() == 13 + first => Ok(SignedEnvelope::Inline(bytes[13..].to_vec())),
        1 if bytes.len() >= 17 => {
            let second =
                u32::from_be_bytes(bytes[13..17].try_into().map_err(|_| CacheError::Corrupt)?)
                    as usize;
            if second == 0 || second > 1024 * 1024 || bytes.len() != 17 + first + second {
                return Err(CacheError::Corrupt);
            }
            Ok(SignedEnvelope::Detached {
                release: bytes[17..17 + first].to_vec(),
                signature: bytes[17 + first..].to_vec(),
            })
        }
        _ => Err(CacheError::Corrupt),
    }
}
fn stage_name() -> Result<String, CacheError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| CacheError::Io)?;
    Ok(format!(
        ".stage-{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
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
