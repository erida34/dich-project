//! Select artifact metadata only from an authenticated Packages index.
use crate::{DebianVersion, Source, VerifiedIndex, parse_control_stanzas};
use std::{error::Error, fmt};

#[derive(Debug, PartialEq, Eq)]
pub enum ArtifactError {
    InvalidIndex,
    NotFound,
    Ambiguous,
    Unsupported,
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
    name: String,
    version: String,
    architecture: String,
    path: String,
    size: u64,
    sha256: [u8; 32],
}
impl IndexedArtifact {
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
        selected = Some(IndexedArtifact {
            source: index.source.clone(),
            name: name.to_owned(),
            version: version.to_owned(),
            architecture: arch.to_owned(),
            path: path.to_owned(),
            size,
            sha256,
        });
    }
    selected.ok_or(ArtifactError::NotFound)
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
            };
            assert!(select_indexed_artifact(&index, "fixture", "1.0-1").is_err());
        }
    }
}
