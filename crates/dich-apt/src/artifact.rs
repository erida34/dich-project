//! Select artifact metadata only from an authenticated Packages index.
use crate::{DebianVersion, Source, ValidatedRelease, VerifiedIndex, parse_control_stanzas};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    io::{Read, Seek, SeekFrom, Write},
    time::SystemTime,
};

#[derive(Debug, PartialEq, Eq)]
pub enum ArtifactError {
    InvalidIndex,
    NotFound,
    Ambiguous,
    Unsupported,
    StaleOrMismatchedRelease,
    Integrity,
    Io,
}
impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid indexed artifact: {self:?}")
    }
}
impl Error for ArtifactError {}

/// Metadata selected from a signature-and-index-verified chain; no artifact has been downloaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedArtifact {
    pub(crate) source: Source,
    release_digest: [u8; 32],
    name: String,
    version: String,
    architecture: String,
    path: String,
    size: u64,
    sha256: [u8; 32],
}

/// Selected artifact bound to the identical fresh Release; it is not downloaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedArtifact {
    artifact: IndexedArtifact,
    release: ValidatedRelease,
}

/// A verified temporary artifact. The underlying file is not exposed for mutation.
#[derive(Debug)]
pub struct VerifiedArtifact {
    file: std::fs::File,
    metadata: IndexedArtifact,
}
impl VerifiedArtifact {
    pub fn metadata(&self) -> &IndexedArtifact {
        &self.metadata
    }
    pub(crate) fn rewind(&mut self) -> Result<(), ArtifactError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map(|_| ())
            .map_err(|_| ArtifactError::Io)
    }
}
impl Read for VerifiedArtifact {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

pub(crate) fn verify_artifact_stream_with_clock(
    authorized: &AuthorizedArtifact,
    mut reader: impl Read,
    max_bytes: u64,
    clock: impl Fn() -> SystemTime,
) -> Result<VerifiedArtifact, ArtifactError> {
    if !authorized.is_valid_at(clock()) {
        return Err(ArtifactError::StaleOrMismatchedRelease);
    }
    let metadata = authorized.artifact();
    if max_bytes == 0 || metadata.size > max_bytes {
        return Err(ArtifactError::Unsupported);
    }
    let mut file = tempfile::tempfile().map_err(|_| ArtifactError::Io)?;
    let mut sha = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let remaining = metadata.size - count;
        let length = buffer
            .len()
            .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
        let n = reader
            .read(&mut buffer[..length])
            .map_err(|_| ArtifactError::Io)?;
        if n > length {
            return Err(ArtifactError::Io);
        }
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(ArtifactError::Integrity)?;
        if count > metadata.size {
            return Err(ArtifactError::Integrity);
        }
        sha.update(&buffer[..n]);
        file.write_all(&buffer[..n])
            .map_err(|_| ArtifactError::Io)?;
    }
    let digest: [u8; 32] = sha.finalize().into();
    if count != metadata.size || digest != metadata.sha256 {
        return Err(ArtifactError::Integrity);
    }
    if !authorized.is_valid_at(clock()) {
        return Err(ArtifactError::StaleOrMismatchedRelease);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ArtifactError::Io)?;
    Ok(VerifiedArtifact {
        file,
        metadata: metadata.clone(),
    })
}
impl AuthorizedArtifact {
    pub fn artifact(&self) -> &IndexedArtifact {
        &self.artifact
    }
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        self.release.is_valid_at(now)
    }
    pub(crate) fn release(&self) -> &ValidatedRelease {
        &self.release
    }
}

/// Bind indexed metadata to the identical Release after source and time validation.
pub fn authorize_artifact(
    release: &ValidatedRelease,
    artifact: &IndexedArtifact,
    now: SystemTime,
) -> Result<AuthorizedArtifact, ArtifactError> {
    let digest: [u8; 32] = Sha256::digest(release.release().contents()).into();
    if !release.is_valid_at(now)
        || release.source() != &artifact.source
        || digest != artifact.release_digest
    {
        return Err(ArtifactError::StaleOrMismatchedRelease);
    }
    Ok(AuthorizedArtifact {
        artifact: artifact.clone(),
        release: release.clone(),
    })
}
impl IndexedArtifact {
    /// Source policy bound to the verified index from which this artifact was selected.
    pub fn source(&self) -> &Source {
        &self.source
    }
    /// SHA256 of the authenticated Release plaintext associated with the index.
    pub fn release_sha256(&self) -> &[u8; 32] {
        &self.release_digest
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Select an exact name and version. Duplicate records, unsafe paths and missing SHA256 fail closed.
pub fn select_indexed_artifact(
    index: &VerifiedIndex,
    name: &str,
    version: &str,
) -> Result<IndexedArtifact, ArtifactError> {
    if !valid_name(name) || DebianVersion::parse(version).is_err() {
        return Err(ArtifactError::Unsupported);
    }
    let stanzas =
        parse_control_stanzas(index.contents()).map_err(|_| ArtifactError::InvalidIndex)?;
    let mut selected = None;
    for stanza in stanzas {
        if stanza.get("package") != Some(name) || stanza.get("version") != Some(version) {
            continue;
        }
        if selected.is_some() {
            return Err(ArtifactError::Ambiguous);
        }
        selected = Some(indexed_stanza(index, &stanza, name, version)?);
    }
    selected.ok_or(ArtifactError::NotFound)
}

/// Select requested identities in one pass; absent identities are omitted for multi-component callers.
pub(crate) fn select_indexed_artifacts(
    index: &VerifiedIndex,
    requested: &std::collections::BTreeSet<(String, String)>,
) -> Result<Vec<IndexedArtifact>, ArtifactError> {
    if requested.len() > 128
        || requested
            .iter()
            .any(|(name, version)| !valid_name(name) || DebianVersion::parse(version).is_err())
    {
        return Err(ArtifactError::Unsupported);
    }
    let stanzas =
        parse_control_stanzas(index.contents()).map_err(|_| ArtifactError::InvalidIndex)?;
    let mut selected = std::collections::BTreeMap::new();
    for stanza in stanzas {
        let (Some(name), Some(version)) = (stanza.get("package"), stanza.get("version")) else {
            continue;
        };
        let identity = (name.to_owned(), version.to_owned());
        if requested.contains(&identity) {
            let artifact = indexed_stanza(index, &stanza, name, version)?;
            if selected.insert(identity, artifact).is_some() {
                return Err(ArtifactError::Ambiguous);
            }
        }
    }
    Ok(selected.into_values().collect())
}

/// `stanza` must originate from this verified index, not an independent input.
fn indexed_stanza(
    index: &VerifiedIndex,
    stanza: &crate::ControlStanza,
    name: &str,
    version: &str,
) -> Result<IndexedArtifact, ArtifactError> {
    let arch = stanza
        .get("architecture")
        .ok_or(ArtifactError::InvalidIndex)?;
    if arch != "all" && arch != index.source.architecture() {
        return Err(ArtifactError::Unsupported);
    }
    let path = stanza
        .get("filename")
        .filter(|s| valid_path(s))
        .ok_or(ArtifactError::InvalidIndex)?;
    let size = stanza
        .get("size")
        .ok_or(ArtifactError::InvalidIndex)?
        .parse::<u64>()
        .map_err(|_| ArtifactError::InvalidIndex)?;
    if size == 0 || size > 8 * 1024 * 1024 * 1024 {
        return Err(ArtifactError::Unsupported);
    }
    let hash = stanza.get("sha256").ok_or(ArtifactError::InvalidIndex)?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ArtifactError::InvalidIndex);
    }
    let mut sha256 = [0; 32];
    for (i, byte) in sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hash[2 * i..2 * i + 2], 16)
            .map_err(|_| ArtifactError::InvalidIndex)?;
    }
    Ok(IndexedArtifact {
        source: index.source.clone(),
        release_digest: index.release_digest,
        name: name.to_owned(),
        version: version.to_owned(),
        architecture: arch.to_owned(),
        path: path.to_owned(),
        size,
        sha256,
    })
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
}
fn valid_path(s: &str) -> bool {
    s.len() <= 4096
        && s.starts_with("pool/")
        && s.ends_with(".deb")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._+-~".contains(&b))
        && s.split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Distribution, SourcePolicy, import_sources};
    #[test]
    fn rejects_url_escape_and_ambiguous_artifact_paths() {
        for bad in [
            "/pool/a.deb",
            "https://x/pool/a.deb",
            "pool/../a.deb",
            "pool/%2e%2e/a.deb",
            "pool/a//b.deb",
            "pool/a.deb?x",
            "pool/a.deb#fragment",
            "pool/a\\b.deb",
        ] {
            assert!(!valid_path(bad), "accepted {bad}");
        }
        assert!(valid_path("pool/main/f/fixture/fixture_1.0-1_amd64.deb"));
    }

    #[test]
    fn rejects_malformed_duplicate_and_wrong_architecture_records() {
        let policy = SourcePolicy::new(
            Distribution::Debian,
            "https://example.org",
            "bookworm",
            &["main"],
            "amd64",
            "/key.gpg",
            &["0123456789ABCDEF0123456789ABCDEF01234567"],
        )
        .unwrap();
        let source = import_sources("Types: deb\nURIs: https://example.org\nSuites: bookworm\nComponents: main\nSigned-By: /key.gpg\n", &policy).unwrap().remove(0);
        let record = "Package: fixture\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/f/fixture/fixture.deb\nSize: 12\nSHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n";
        for bad in [
            format!("{record}{record}"),
            record.replace("pool/main/f/fixture/fixture.deb", "pool/../escape.deb"),
            record.replace("Architecture: amd64", "Architecture: arm64"),
            record.replace("SHA256:", "SHA1:"),
            record.replace("Size: 12", "Size: 0"),
        ] {
            let index = VerifiedIndex {
                contents: bad.into_bytes(),
                source: source.clone(),
                release_digest: [0; 32],
            };
            assert!(select_indexed_artifact(&index, "fixture", "1.0-1").is_err());
            let requested =
                std::collections::BTreeSet::from([("fixture".to_string(), "1.0-1".to_string())]);
            assert!(select_indexed_artifacts(&index, &requested).is_err());
        }
    }
}
