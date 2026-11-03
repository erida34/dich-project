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
const MANIFEST_PREFIX: &[u8] = b"dich.profile.generation\0v2\0";
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
    pub graph_id: String,
    pub graph: ReferenceGraph,
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
        validate_profile_name(profile_name)?;
        let graph = self.read_reference_graph(graph_id)?;
        let profiles = private_dir(&self.root, "profiles")?;
        let profile = private_dir(&profiles, profile_name)?;
        let generations = private_dir(&profile, "generations")?;
        let current = read_profile_dir(self, &profile, profile_name)?;
        if let Some(current) = &current
            && current.graph_id == graph_id
        {
            return Ok((current.clone(), ProfileOutcome::Reused));
        }
        let previous_id = current.map(|generation| generation.generation_id);
        let manifest = encode_manifest(
            profile_name,
            graph_id,
            previous_id.as_deref(),
            graph.canonical(),
        )?;
        let generation_id = hash_hex(&manifest);
        publish_manifest(&generations, &generation_id, &manifest)?;
        fs::fsync(&generations).map_err(|_| PublicationError::Io)?;
        switch_current(&profile, &generation_id)?;

        Ok((
            ProfileGeneration {
                profile: profile_name.to_owned(),
                generation_id,
                previous_id,
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
        validate_profile_name(profile_name)?;
        let profiles = open_private_dir(&self.root, "profiles")?;
        let profile = open_private_dir(&profiles, profile_name)?;
        let current =
            read_profile_dir(self, &profile, profile_name)?.ok_or(PublicationError::Unsupported)?;
        let previous = current.previous_id.ok_or(PublicationError::Unsupported)?;
        let generations = open_private_dir(&profile, "generations")?;
        let generation = read_generation(self, &generations, profile_name, &previous)?;
        switch_current(&profile, &generation.generation_id)?;
        Ok(generation)
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
    let target = match fs::readlinkat(profile, "current", Vec::new()) {
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
    let (manifest_profile, graph_id, previous_id, graph_bytes) = decode_manifest(&bytes)?;
    if manifest_profile != profile_name {
        return Err(PublicationError::Integrity);
    }
    let graph =
        ReferenceGraph::from_canonical(&graph_bytes).map_err(|_| PublicationError::Integrity)?;
    if hash_hex(&graph_bytes) != graph_id {
        return Err(PublicationError::Integrity);
    }
    let recorded = db.read_reference_graph(&graph_id)?;
    if recorded != graph {
        return Err(PublicationError::Integrity);
    }
    Ok(ProfileGeneration {
        profile: profile_name.to_owned(),
        generation_id: generation_id.to_owned(),
        previous_id,
        graph_id,
        graph,
    })
}

fn switch_current(profile: &OwnedFd, generation_id: &str) -> Result<(), PublicationError> {
    validate_digest(generation_id)?;
    let target = format!("generations/{generation_id}");
    let link_name = random_name("current")?;
    fs::symlinkat(&target, profile, &link_name).map_err(|_| PublicationError::Io)?;
    let mut link = TempEntry {
        dir: profile,
        name: Some(link_name.clone()),
    };
    fs::fsync(profile).map_err(|_| PublicationError::Io)?;
    fs::renameat(profile, &link_name, profile, "current").map_err(|_| PublicationError::Io)?;
    link.name = None;
    fs::fsync(profile).map_err(|_| PublicationError::Io)
}

fn publish_manifest(
    generations: &OwnedFd,
    generation_id: &str,
    bytes: &[u8],
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
    file.sync_all().map_err(|_| PublicationError::Io)?;
    fs::fchmod(&file, Mode::from_raw_mode(0o400)).map_err(|_| PublicationError::Io)?;
    file.sync_all().map_err(|_| PublicationError::Io)?;
    drop(file);

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
    graph: &[u8],
) -> Result<Vec<u8>, PublicationError> {
    if graph.len() > MAX_MANIFEST_BYTES {
        return Err(PublicationError::Limit);
    }
    let mut bytes = MANIFEST_PREFIX.to_vec();
    append_field(&mut bytes, profile_name.as_bytes())?;
    append_field(&mut bytes, graph_id.as_bytes())?;
    append_field(&mut bytes, previous_id.unwrap_or("").as_bytes())?;
    append_field(&mut bytes, graph)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(PublicationError::Limit);
    }
    Ok(bytes)
}

fn decode_manifest(
    bytes: &[u8],
) -> Result<(String, String, Option<String>, Vec<u8>), PublicationError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(PublicationError::Integrity);
    }
    let (prefix, has_previous) = if bytes.starts_with(MANIFEST_PREFIX) {
        (MANIFEST_PREFIX, true)
    } else if bytes.starts_with(LEGACY_MANIFEST_PREFIX) {
        (LEGACY_MANIFEST_PREFIX, false)
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
    let canonical = if has_previous {
        encode_manifest(&profile, &graph_id, previous_id.as_deref(), &graph)?
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
    Ok((profile, graph_id, previous_id, graph))
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

        assert_eq!(
            decode_manifest(&legacy).unwrap(),
            ("default".into(), graph_id, None, graph.to_vec())
        );
    }
}
