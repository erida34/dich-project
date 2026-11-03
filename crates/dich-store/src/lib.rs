#![forbid(unsafe_code)]
//! Store identity and future durable storage.

use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityMaterial {
    name: String,
    version: String,
    architecture: String,
    distribution: String,
    suite: String,
    uri: String,
    source_architecture: String,
    components: Vec<String>,
    fingerprints: Vec<String>,
    artifact_path: String,
    artifact_size: u64,
    artifact_sha256: [u8; 32],
    release_sha256: [u8; 32],
    policy: u32,
}
#[derive(Debug, PartialEq, Eq)]
pub struct StoreIdentity {
    digest: [u8; 32],
    canonical: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityComparison {
    Different,
    SameIdentity,
    Collision,
}
#[derive(Debug, Clone, Copy)]
pub enum TransformPolicy {
    PrivateRegularFilesV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    Invalid,
    Unverified,
}
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store identity failed: {self:?}")
    }
}
impl Error for IdentityError {}
impl StoreIdentity {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn hex(&self) -> String {
        self.digest.iter().map(|b| format!("{b:02x}")).collect()
    }
    /// SameIdentity does not authorize reuse without comparing actual stored content.
    pub fn compare(&self, other: &Self) -> IdentityComparison {
        if self.digest != other.digest {
            IdentityComparison::Different
        } else if self.canonical == other.canonical {
            IdentityComparison::SameIdentity
        } else {
            IdentityComparison::Collision
        }
    }
    /// Derive identity only after the journal has rechecked the artifact, authorization and source floor.
    #[cfg(target_os = "linux")]
    pub fn from_cached(
        journal: &dich_apt::SnapshotJournal,
        authorized: &dich_apt::AuthorizedArtifact,
        policy: TransformPolicy,
    ) -> Result<Self, IdentityError> {
        let verified = journal
            .load_artifact(authorized)
            .map_err(|_| IdentityError::Unverified)?;
        let artifact = verified.metadata();
        if artifact != authorized.artifact()
            || !authorized.is_valid_at(std::time::SystemTime::now())
        {
            return Err(IdentityError::Unverified);
        }
        let source = artifact.source();
        let material = IdentityMaterial {
            name: artifact.name().into(),
            version: artifact.version().into(),
            architecture: artifact.architecture().into(),
            distribution: match source.distribution() {
                dich_apt::Distribution::Debian => "debian",
                dich_apt::Distribution::Ubuntu => "ubuntu",
            }
            .into(),
            suite: source.suite().into(),
            uri: source.uri().into(),
            source_architecture: source.architecture().into(),
            components: source.components().to_vec(),
            fingerprints: source.fingerprints().to_vec(),
            artifact_path: artifact.path().into(),
            artifact_size: artifact.size(),
            artifact_sha256: *artifact.sha256(),
            release_sha256: *artifact.release_sha256(),
            policy: match policy {
                TransformPolicy::PrivateRegularFilesV1 => 1,
            },
        };
        let identity = identity_from_material(material)?;
        if !authorized.is_valid_at(std::time::SystemTime::now()) {
            return Err(IdentityError::Unverified);
        }
        Ok(identity)
    }
}
fn identity_from_material(mut material: IdentityMaterial) -> Result<StoreIdentity, IdentityError> {
    fn add(out: &mut Vec<u8>, data: &[u8]) -> Result<(), IdentityError> {
        if data.is_empty() || data.len() > 4096 {
            return Err(IdentityError::Invalid);
        }
        let len = u32::try_from(data.len()).map_err(|_| IdentityError::Invalid)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(data);
        Ok(())
    }
    fn add_set(out: &mut Vec<u8>, values: &mut [String]) -> Result<(), IdentityError> {
        if values.is_empty() || values.len() > 128 {
            return Err(IdentityError::Invalid);
        }
        values.sort_unstable();
        if values.windows(2).any(|w| w[0] == w[1]) {
            return Err(IdentityError::Invalid);
        }
        out.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for value in values {
            add(out, value.as_bytes())?;
        }
        Ok(())
    }
    if material.policy == 0 || material.artifact_size == 0 {
        return Err(IdentityError::Invalid);
    }
    let mut canonical = b"dich.store.identity\0v1\0".to_vec();
    for value in [
        &material.name,
        &material.version,
        &material.architecture,
        &material.distribution,
        &material.suite,
        &material.uri,
        &material.source_architecture,
    ] {
        add(&mut canonical, value.as_bytes())?;
    }
    add_set(&mut canonical, &mut material.components)?;
    add_set(&mut canonical, &mut material.fingerprints)?;
    add(&mut canonical, material.artifact_path.as_bytes())?;
    canonical.extend_from_slice(&material.artifact_size.to_be_bytes());
    canonical.extend_from_slice(&material.artifact_sha256);
    canonical.extend_from_slice(&material.release_sha256);
    canonical.extend_from_slice(&material.policy.to_be_bytes());
    let digest = Sha256::digest(&canonical).into();
    Ok(StoreIdentity { digest, canonical })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn material() -> IdentityMaterial {
        IdentityMaterial {
            name: "sample".into(),
            version: "1.0-1".into(),
            architecture: "amd64".into(),
            distribution: "debian".into(),
            suite: "bookworm".into(),
            uri: "https://example.org/debian".into(),
            source_architecture: "amd64".into(),
            components: vec!["main".into(), "contrib".into()],
            fingerprints: vec!["ABCDEF".into(), "012345".into()],
            artifact_path: "pool/main/s/sample.deb".into(),
            artifact_size: 42,
            artifact_sha256: [1; 32],
            release_sha256: [2; 32],
            policy: 1,
        }
    }
    #[test]
    fn identity_is_stable_and_normalizes_sets() {
        let a = material();
        let mut b = material();
        b.components.reverse();
        b.fingerprints.reverse();
        let identity = identity_from_material(a).unwrap();
        assert_eq!(
            identity.hex(),
            "cc96fcc56e8ec7e8361813d14c05f77caf11cae76d6fd809f89ffaa815d83515"
        );
        assert_eq!(identity, identity_from_material(b).unwrap());
    }
    #[test]
    fn identity_changes_for_content_source_snapshot_arch_or_policy() {
        let base = identity_from_material(material()).unwrap();
        let mut variants = Vec::new();
        let mut v = material();
        v.artifact_sha256[0] ^= 1;
        variants.push(v);
        let mut v = material();
        v.release_sha256[0] ^= 1;
        variants.push(v);
        let mut v = material();
        v.uri.push('x');
        variants.push(v);
        let mut v = material();
        v.architecture = "arm64".into();
        variants.push(v);
        let mut v = material();
        v.policy = 2;
        variants.push(v);
        for variant in variants {
            assert_ne!(
                base.digest(),
                identity_from_material(variant).unwrap().digest()
            );
        }
    }
    #[test]
    fn collision_or_ambiguous_sets_never_imply_reuse() {
        let a = identity_from_material(material()).unwrap();
        let mut b = identity_from_material({
            let mut v = material();
            v.uri.push('x');
            v
        })
        .unwrap();
        b.digest = a.digest;
        assert_eq!(a.compare(&b), IdentityComparison::Collision);
        let mut duplicate = material();
        duplicate.components.push("main".into());
        assert!(identity_from_material(duplicate).is_err());
    }
    #[test]
    fn canonical_field_framing_and_limits_are_unambiguous() {
        let mut a = material();
        a.name = "ab".into();
        a.version = "c".into();
        let mut b = material();
        b.name = "a".into();
        b.version = "bc".into();
        assert_ne!(
            identity_from_material(a).unwrap().digest(),
            identity_from_material(b).unwrap().digest()
        );
        let mut bad = material();
        bad.uri = "x".repeat(4097);
        assert!(identity_from_material(bad).is_err());
    }
}
