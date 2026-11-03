//! Immutable profile generations published through one atomic relative symlink.
use crate::{
    MetadataDb, PublicationError,
    publication::{open_private_dir, private_dir},
};
use dich_core::reference_graph::ReferenceGraph;
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::fd::OwnedFd,
};

const LEGACY_MANIFEST_PREFIX: &[u8] = b"dich.profile.generation\0v1\0";
const PARENT_MANIFEST_PREFIX: &[u8] = b"dich.profile.generation\0v2\0";
const MANIFEST_PREFIX: &[u8] = b"dich.profile.generation\0v3\0";
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileOutcome {
    Switched,
    Reused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileGeneration {
    pub profile: String,
    pub generation_id: String,
    pub previous_id: Option<String>,
    pub requested_package: Option<String>,
    pub graph_id: String,
    pub graph: ReferenceGraph,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileFailurePoint {
    None,
    BeforeManifestSync,
    AfterManifestSync,
    AfterManifestRename,
    AfterGenerationsSync,
    BeforeCurrentRename,
    AfterCurrentRename,
    AfterProfileSync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RollbackFailurePoint {
    None,
    BeforeRollbackSwitch,
    AfterRollbackSwitch,
    AfterRemovedUnlink,
}

fn fail_profile(
    actual: ProfileFailurePoint,
    expected: ProfileFailurePoint,
) -> Result<(), PublicationError> {
    if actual == expected {
        #[cfg(test)]
        if std::env::var_os("DICH_INJECT_PROCESS_EXIT").is_some() {
            std::process::exit(88);
        }
        Err(PublicationError::Injected)
    } else {
        Ok(())
    }
}

fn fail_rollback(
    actual: RollbackFailurePoint,
    expected: RollbackFailurePoint,
) -> Result<(), PublicationError> {
    if actual == expected {
        #[cfg(test)]
        if std::env::var_os("DICH_INJECT_PROCESS_EXIT").is_some() {
            std::process::exit(89);
        }
        Err(PublicationError::Injected)
    } else {
        Ok(())
    }
}

impl MetadataDb {
    /// Publish a graph-backed immutable manifest and atomically switch the profile's `current` symlink.
    /// The graph must already reference committed private trees. This records profile metadata only;
    /// it does not install, expose, or activate any package files.
    pub fn publish_profile_generation(
        &mut self,
        profile_name: &str,
        graph_id: &str,
    ) -> Result<(ProfileGeneration, ProfileOutcome), PublicationError> {
        self.publish_profile_generation_inner(profile_name, None, graph_id)
    }

    /// Publish a package-labelled profile generation. The label identifies the requested root;
    /// the graph still contains every committed object selected by the resolver.
    pub fn publish_package_profile_generation(
        &mut self,
        profile_name: &str,
        requested_package: &str,
        graph_id: &str,
    ) -> Result<(ProfileGeneration, ProfileOutcome), PublicationError> {
        validate_package_name(requested_package)?;
        self.publish_profile_generation_inner(profile_name, Some(requested_package), graph_id)
    }

    fn publish_profile_generation_inner(
        &mut self,
        profile_name: &str,
        requested_package: Option<&str>,
        graph_id: &str,
    ) -> Result<(ProfileGeneration, ProfileOutcome), PublicationError> {
        self.publish_profile_generation_with_failure(
            profile_name,
            requested_package,
            graph_id,
            ProfileFailurePoint::None,
        )
    }

    pub(crate) fn publish_profile_generation_with_failure(
        &mut self,
        profile_name: &str,
        requested_package: Option<&str>,
        graph_id: &str,
        failure: ProfileFailurePoint,
    ) -> Result<(ProfileGeneration, ProfileOutcome), PublicationError> {
        validate_profile_name(profile_name)?;
        let graph = self.read_reference_graph(graph_id)?;
        let profiles = private_dir(&self.root, "profiles")?;
        let profile = private_dir(&profiles, profile_name)?;
        let generations = private_dir(&profile, "generations")?;
        let current = read_profile_dir(self, &profile, profile_name)?;
        if let Some(current) = &current
            && current.graph_id == graph_id
            && current.requested_package.as_deref() == requested_package
        {
            return Ok((current.clone(), ProfileOutcome::Reused));
        }
        let removed = if current.is_none() {
            read_removed_profile_dir(self, &profile, profile_name)?
        } else {
            None
        };
        if let Some(removed) = &removed
            && removed.requested_package.as_deref() != requested_package
        {
            return Err(PublicationError::Unsupported);
        }
        let previous_id = match current {
            Some(generation) => Some(generation.generation_id),
            None => removed.map(|generation| generation.generation_id),
        };
        let manifest = encode_manifest(
            profile_name,
            graph_id,
            previous_id.as_deref(),
            requested_package,
            graph.canonical(),
        )?;
        let generation_id = hash_hex(&manifest);
        publish_manifest(&generations, &generation_id, &manifest, failure)?;
        fs::fsync(&generations).map_err(|_| PublicationError::Io)?;
        fail_profile(failure, ProfileFailurePoint::AfterGenerationsSync)?;
        switch_current(&profile, &generation_id, failure)?;

        Ok((
            ProfileGeneration {
                profile: profile_name.to_owned(),
                generation_id,
                previous_id,
                requested_package: requested_package.map(str::to_owned),
                graph_id: graph_id.to_owned(),
                graph,
            },
            ProfileOutcome::Switched,
        ))
    }

    /// Read the generation selected by a profile's validated `current` symlink.
    pub fn read_profile_generation(
        &self,
        profile_name: &str,
    ) -> Result<Option<ProfileGeneration>, PublicationError> {
        validate_profile_name(profile_name)?;
        let Some(profiles) = open_optional_private_dir(&self.root, "profiles")? else {
            return Ok(None);
        };
        let Some(profile) = open_optional_private_dir(&profiles, profile_name)? else {
            return Ok(None);
        };
        read_profile_dir(self, &profile, profile_name)
    }

    /// Atomically move a profile pointer to the generation recorded as its previous state.
    pub fn rollback_profile_generation(
        &mut self,
        profile_name: &str,
    ) -> Result<ProfileGeneration, PublicationError> {
        self.rollback_profile_generation_with_failure(profile_name, RollbackFailurePoint::None)
    }

    pub(crate) fn rollback_profile_generation_with_failure(
        &mut self,
        profile_name: &str,
        failure: RollbackFailurePoint,
    ) -> Result<ProfileGeneration, PublicationError> {
        validate_profile_name(profile_name)?;
        let profiles = open_private_dir(&self.root, "profiles")?;
        let profile = open_private_dir(&profiles, profile_name)?;
        let (current, was_removed) = match read_profile_dir(self, &profile, profile_name)? {
            Some(current) => (current, false),
            None => (
                read_removed_profile_dir(self, &profile, profile_name)?
                    .ok_or(PublicationError::Unsupported)?,
                true,
            ),
        };
        let previous = current.previous_id.ok_or(PublicationError::Unsupported)?;
        let generations = open_private_dir(&profile, "generations")?;
        let generation = read_generation(self, &generations, profile_name, &previous)?;
        fail_rollback(failure, RollbackFailurePoint::BeforeRollbackSwitch)?;
        switch_current(
            &profile,
            &generation.generation_id,
            ProfileFailurePoint::None,
        )?;
        fail_rollback(failure, RollbackFailurePoint::AfterRollbackSwitch)?;
        if was_removed {
            fs::unlinkat(&profile, "removed", AtFlags::empty())
                .map_err(|_| PublicationError::Io)?;
            fs::fsync(&profile).map_err(|_| PublicationError::Io)?;
            fail_rollback(failure, RollbackFailurePoint::AfterRemovedUnlink)?;
        }
        Ok(generation)
    }

    /// Move the selected package generation to an inactive pointer. Its history remains available
    /// for rollback, and its objects remain referenced by immutable manifests.
    pub fn remove_package_profile_generation(
        &mut self,
        profile_name: &str,
        requested_package: &str,
    ) -> Result<ProfileGeneration, PublicationError> {
        validate_profile_name(profile_name)?;
        validate_package_name(requested_package)?;
        let profiles = open_private_dir(&self.root, "profiles")?;
        let profile = open_private_dir(&profiles, profile_name)?;
        let current =
            read_profile_dir(self, &profile, profile_name)?.ok_or(PublicationError::Unsupported)?;
        if current.requested_package.as_deref() != Some(requested_package) {
            return Err(PublicationError::Unsupported);
        }
        // Validate an existing tombstone before replacing it; never overwrite an unknown entry.
        let _ = read_removed_profile_dir(self, &profile, profile_name)?;
        if fs::readlinkat(&profile, "removed", Vec::new()).is_ok() {
            fs::unlinkat(&profile, "removed", AtFlags::empty())
                .map_err(|_| PublicationError::Io)?;
        }
        fs::renameat(&profile, "current", &profile, "removed").map_err(|_| PublicationError::Io)?;
        fs::fsync(&profile).map_err(|_| PublicationError::Io)?;
        Ok(current)
    }

    /// List active profile generations in stable name order. Incomplete profile directories
    /// without a current pointer are ignored; malformed pointers or manifests fail closed.
    pub fn list_profiles(&self) -> Result<Vec<ProfileGeneration>, PublicationError> {
        let Some(profiles) = open_optional_private_dir(&self.root, "profiles")? else {
            return Ok(Vec::new());
        };
        let mut entries = fs::Dir::read_from(&profiles).map_err(|_| PublicationError::Io)?;
        let mut names = Vec::new();
        while let Some(entry) = entries.read() {
            let entry = entry.map_err(|_| PublicationError::Io)?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            let name = std::str::from_utf8(bytes).map_err(|_| PublicationError::UnsafePath)?;
            validate_profile_name(name)?;
            names.push(name.to_owned());
        }
        names.sort();
        let mut output = Vec::new();
        for name in names {
            let profile = open_private_dir(&profiles, &name)?;
            if let Some(generation) = read_profile_dir(self, &profile, &name)? {
                output.push(generation);
            }
        }
        Ok(output)
    }
}

fn read_profile_dir(
    db: &MetadataDb,
    profile: &OwnedFd,
    profile_name: &str,
) -> Result<Option<ProfileGeneration>, PublicationError> {
    read_pointer_generation(db, profile, profile_name, "current")
}

fn read_removed_profile_dir(
    db: &MetadataDb,
    profile: &OwnedFd,
    profile_name: &str,
) -> Result<Option<ProfileGeneration>, PublicationError> {
    read_pointer_generation(db, profile, profile_name, "removed")
}

fn read_pointer_generation(
    db: &MetadataDb,
    profile: &OwnedFd,
    profile_name: &str,
    pointer_name: &str,
) -> Result<Option<ProfileGeneration>, PublicationError> {
    let target = match fs::readlinkat(profile, pointer_name, Vec::new()) {
        Ok(target) => target,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(PublicationError::UnsafePath),
    };
    let target =
        std::str::from_utf8(target.to_bytes()).map_err(|_| PublicationError::UnsafePath)?;
    let generation_id = target
        .strip_prefix("generations/")
        .ok_or(PublicationError::UnsafePath)?;
    validate_digest(generation_id)?;

    let generations = open_private_dir(profile, "generations")?;
    read_generation(db, &generations, profile_name, generation_id).map(Some)
}

fn read_generation(
    db: &MetadataDb,
    generations: &OwnedFd,
    profile_name: &str,
    generation_id: &str,
) -> Result<ProfileGeneration, PublicationError> {
    let bytes = read_manifest(generations, generation_id)?;
    if hash_hex(&bytes) != generation_id {
        return Err(PublicationError::Integrity);
    }
    let manifest = decode_manifest(&bytes)?;
    if manifest.profile != profile_name {
        return Err(PublicationError::Integrity);
    }
    let graph =
        ReferenceGraph::from_canonical(&manifest.graph).map_err(|_| PublicationError::Integrity)?;
    if hash_hex(&manifest.graph) != manifest.graph_id {
        return Err(PublicationError::Integrity);
    }
    let recorded = db.read_reference_graph(&manifest.graph_id)?;
    if recorded != graph {
        return Err(PublicationError::Integrity);
    }
    Ok(ProfileGeneration {
        profile: profile_name.to_owned(),
        generation_id: generation_id.to_owned(),
        previous_id: manifest.previous_id,
        requested_package: manifest.requested_package,
        graph_id: manifest.graph_id,
        graph,
    })
}

fn switch_current(
    profile: &OwnedFd,
    generation_id: &str,
    failure: ProfileFailurePoint,
) -> Result<(), PublicationError> {
    validate_digest(generation_id)?;
    let target = format!("generations/{generation_id}");
    let link_name = random_name("current")?;
    fs::symlinkat(&target, profile, &link_name).map_err(|_| PublicationError::Io)?;
    let mut link = TempEntry {
        dir: profile,
        name: Some(link_name.clone()),
    };
    fs::fsync(profile).map_err(|_| PublicationError::Io)?;
    fail_profile(failure, ProfileFailurePoint::BeforeCurrentRename)?;
    fs::renameat(profile, &link_name, profile, "current").map_err(|_| PublicationError::Io)?;
    link.name = None;
    fail_profile(failure, ProfileFailurePoint::AfterCurrentRename)?;
    fs::fsync(profile).map_err(|_| PublicationError::Io)?;
    fail_profile(failure, ProfileFailurePoint::AfterProfileSync)
}

fn publish_manifest(
    generations: &OwnedFd,
    generation_id: &str,
    bytes: &[u8],
    failure: ProfileFailurePoint,
) -> Result<(), PublicationError> {
    let temp_name = random_name("generation")?;
    let fd = fs::openat(
        generations,
        &temp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| PublicationError::Io)?;
    let mut cleanup = TempEntry {
        dir: generations,
        name: Some(temp_name.clone()),
    };
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).map_err(|_| PublicationError::Io)?;
    fail_profile(failure, ProfileFailurePoint::BeforeManifestSync)?;
    file.sync_all().map_err(|_| PublicationError::Io)?;
    fs::fchmod(&file, Mode::from_raw_mode(0o400)).map_err(|_| PublicationError::Io)?;
    file.sync_all().map_err(|_| PublicationError::Io)?;
    drop(file);
    fail_profile(failure, ProfileFailurePoint::AfterManifestSync)?;

    match fs::renameat_with(
        generations,
        &temp_name,
        generations,
        generation_id,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => cleanup.name = None,
        Err(rustix::io::Errno::EXIST) => {
            if read_manifest(generations, generation_id)? != bytes {
                return Err(PublicationError::Collision);
            }
        }
        Err(_) => return Err(PublicationError::Io),
    }
    fail_profile(failure, ProfileFailurePoint::AfterManifestRename)?;
    Ok(())
}

fn read_manifest(generations: &OwnedFd, generation_id: &str) -> Result<Vec<u8>, PublicationError> {
    let fd = fs::openat(
        generations,
        generation_id,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| PublicationError::UnsafePath)?;
    let stat = fs::fstat(&fd).map_err(|_| PublicationError::Io)?;
    let dir_stat = fs::fstat(generations).map_err(|_| PublicationError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || stat.st_size as usize > MAX_MANIFEST_BYTES
        || stat.st_nlink != 1
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || stat.st_mode & 0o7777 != 0o400
        || stat.st_dev != dir_stat.st_dev
    {
        return Err(PublicationError::UnsafePath);
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    std::fs::File::from(fd)
        .take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PublicationError::Io)?;
    if bytes.len() != stat.st_size as usize || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(PublicationError::Integrity);
    }
    Ok(bytes)
}

fn encode_manifest(
    profile_name: &str,
    graph_id: &str,
    previous_id: Option<&str>,
    requested_package: Option<&str>,
    graph: &[u8],
) -> Result<Vec<u8>, PublicationError> {
    if graph.len() > MAX_MANIFEST_BYTES {
        return Err(PublicationError::Limit);
    }
    let mut bytes = MANIFEST_PREFIX.to_vec();
    append_field(&mut bytes, profile_name.as_bytes())?;
    append_field(&mut bytes, graph_id.as_bytes())?;
    append_field(&mut bytes, previous_id.unwrap_or("").as_bytes())?;
    append_field(&mut bytes, requested_package.unwrap_or("").as_bytes())?;
    append_field(&mut bytes, graph)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(PublicationError::Limit);
    }
    Ok(bytes)
}

struct DecodedManifest {
    profile: String,
    graph_id: String,
    previous_id: Option<String>,
    requested_package: Option<String>,
    graph: Vec<u8>,
}

fn decode_manifest(bytes: &[u8]) -> Result<DecodedManifest, PublicationError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(PublicationError::Integrity);
    }
    let (prefix, has_previous, has_package) = if bytes.starts_with(MANIFEST_PREFIX) {
        (MANIFEST_PREFIX, true, true)
    } else if bytes.starts_with(PARENT_MANIFEST_PREFIX) {
        (PARENT_MANIFEST_PREFIX, true, false)
    } else if bytes.starts_with(LEGACY_MANIFEST_PREFIX) {
        (LEGACY_MANIFEST_PREFIX, false, false)
    } else {
        return Err(PublicationError::Integrity);
    };
    let mut cursor = std::io::Cursor::new(&bytes[prefix.len()..]);
    let profile = read_field(&mut cursor, 64)?;
    let graph_id = read_field(&mut cursor, 64)?;
    let previous_id = if has_previous {
        read_field(&mut cursor, 64)?
    } else {
        Vec::new()
    };
    let requested_package = if has_package {
        read_field(&mut cursor, 128)?
    } else {
        Vec::new()
    };
    let graph = read_field_bytes(&mut cursor, MAX_MANIFEST_BYTES)?.to_vec();
    if cursor.position() as usize != bytes.len() - prefix.len() {
        return Err(PublicationError::Integrity);
    }
    let profile = std::str::from_utf8(&profile)
        .map_err(|_| PublicationError::Integrity)?
        .to_owned();
    validate_profile_name(&profile)?;
    let graph_id = String::from_utf8(graph_id).map_err(|_| PublicationError::Integrity)?;
    validate_digest(&graph_id)?;
    let previous_id = String::from_utf8(previous_id).map_err(|_| PublicationError::Integrity)?;
    let previous_id = if previous_id.is_empty() {
        None
    } else {
        validate_digest(&previous_id)?;
        Some(previous_id)
    };
    let requested_package =
        String::from_utf8(requested_package).map_err(|_| PublicationError::Integrity)?;
    let requested_package = if requested_package.is_empty() {
        None
    } else {
        validate_package_name(&requested_package)?;
        Some(requested_package)
    };
    let canonical = if has_package {
        encode_manifest(
            &profile,
            &graph_id,
            previous_id.as_deref(),
            requested_package.as_deref(),
            &graph,
        )?
    } else if has_previous {
        let mut parent = PARENT_MANIFEST_PREFIX.to_vec();
        append_field(&mut parent, profile.as_bytes())?;
        append_field(&mut parent, graph_id.as_bytes())?;
        append_field(&mut parent, previous_id.as_deref().unwrap_or("").as_bytes())?;
        append_field(&mut parent, &graph)?;
        parent
    } else {
        let mut legacy = LEGACY_MANIFEST_PREFIX.to_vec();
        append_field(&mut legacy, profile.as_bytes())?;
        append_field(&mut legacy, graph_id.as_bytes())?;
        append_field(&mut legacy, &graph)?;
        legacy
    };
    if canonical != bytes {
        return Err(PublicationError::Integrity);
    }
    Ok(DecodedManifest {
        profile,
        graph_id,
        previous_id,
        requested_package,
        graph,
    })
}

fn validate_package_name(name: &str) -> Result<(), PublicationError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(byte))
    {
        return Err(PublicationError::UnsafePath);
    }
    Ok(())
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PublicationError> {
    let length = u32::try_from(value.len()).map_err(|_| PublicationError::Limit)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn read_field(
    cursor: &mut std::io::Cursor<&[u8]>,
    max: usize,
) -> Result<Vec<u8>, PublicationError> {
    Ok(read_field_bytes(cursor, max)?.to_vec())
}

fn read_field_bytes<'a>(
    cursor: &mut std::io::Cursor<&'a [u8]>,
    max: usize,
) -> Result<&'a [u8], PublicationError> {
    let mut length = [0u8; 4];
    cursor
        .read_exact(&mut length)
        .map_err(|_| PublicationError::Integrity)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max {
        return Err(PublicationError::Limit);
    }
    let start = cursor.position() as usize;
    let end = start.checked_add(length).ok_or(PublicationError::Limit)?;
    let value = cursor
        .get_ref()
        .get(start..end)
        .ok_or(PublicationError::Integrity)?;
    cursor.set_position(end as u64);
    Ok(value)
}

fn validate_profile_name(name: &str) -> Result<(), PublicationError> {
    let mut bytes = name.bytes();
    if name.len() > 64
        || !bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        || !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(PublicationError::UnsafePath);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), PublicationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PublicationError::UnsafePath);
    }
    Ok(())
}

fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn random_name(prefix: &str) -> Result<String, PublicationError> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| PublicationError::Io)?;
    Ok(format!(
        ".{prefix}-{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn open_optional_private_dir(
    parent: &OwnedFd,
    name: &str,
) -> Result<Option<OwnedFd>, PublicationError> {
    let fd = match fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(PublicationError::UnsafePath),
    };
    let stat = fs::fstat(&fd).map_err(|_| PublicationError::Io)?;
    let parent_stat = fs::fstat(parent).map_err(|_| PublicationError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || stat.st_mode & 0o7077 != 0
        || stat.st_dev != parent_stat.st_dev
    {
        return Err(PublicationError::UnsafePath);
    }
    Ok(Some(fd))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_legacy_generation_without_rollback_parent() {
        let profile = b"default";
        let graph_id = "a".repeat(64);
        let graph = b"legacy canonical graph";
        let mut legacy = LEGACY_MANIFEST_PREFIX.to_vec();
        append_field(&mut legacy, profile).unwrap();
        append_field(&mut legacy, graph_id.as_bytes()).unwrap();
        append_field(&mut legacy, graph).unwrap();

        let decoded = decode_manifest(&legacy).unwrap();
        assert_eq!(decoded.profile, "default");
        assert_eq!(decoded.graph_id, graph_id);
        assert_eq!(decoded.previous_id, None);
        assert_eq!(decoded.requested_package, None);
        assert_eq!(decoded.graph, graph);
    }

    #[test]
    fn decodes_v2_generation_without_package_label() {
        let profile = b"default";
        let graph_id = "a".repeat(64);
        let previous_id = "b".repeat(64);
        let graph = b"v2 canonical graph";
        let mut v2 = PARENT_MANIFEST_PREFIX.to_vec();
        append_field(&mut v2, profile).unwrap();
        append_field(&mut v2, graph_id.as_bytes()).unwrap();
        append_field(&mut v2, previous_id.as_bytes()).unwrap();
        append_field(&mut v2, graph).unwrap();

        let decoded = decode_manifest(&v2).unwrap();
        assert_eq!(decoded.profile, "default");
        assert_eq!(decoded.graph_id, graph_id);
        assert_eq!(decoded.previous_id, Some(previous_id));
        assert_eq!(decoded.requested_package, None);
        assert_eq!(decoded.graph, graph);
    }
}
