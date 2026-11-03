#![forbid(unsafe_code)]
//! Store identity and future durable storage.

#[cfg(target_os = "linux")]
mod graph;
#[cfg(target_os = "linux")]
mod inspect;
#[cfg(target_os = "linux")]
mod metadata;
#[cfg(target_os = "linux")]
mod publication;
#[cfg(target_os = "linux")]
mod recovery;
#[cfg(target_os = "linux")]
mod tree;
#[cfg(target_os = "linux")]
pub use graph::GraphOutcome;
#[cfg(target_os = "linux")]
pub use inspect::{ObjectKind, ObjectRecord};
#[cfg(target_os = "linux")]
pub use metadata::{MetadataDb, MetadataError};
#[cfg(target_os = "linux")]
pub use publication::{ArchiveVerification, PublicationError, PublicationOutcome};
#[cfg(target_os = "linux")]
pub use recovery::{OrphanKind, RecoveryInventory};
#[cfg(target_os = "linux")]
pub use tree::{TreeOutcome, TreeVerification};

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
    VerifiedArchiveV1,
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
                TransformPolicy::VerifiedArchiveV1 => 2,
            },
        };
        let identity = identity_from_material(material)?;
        if !authorized.is_valid_at(std::time::SystemTime::now()) {
            return Err(IdentityError::Unverified);
        }
        Ok(identity)
    }
}
#[cfg(target_os = "linux")]
fn verify_identity_context(
    id: &str,
    context: &[u8],
    policy: u32,
) -> Result<(u64, [u8; 32]), crate::PublicationError> {
    use crate::PublicationError;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PublicationError::UnsafePath);
    }
    if !context.starts_with(b"dich.store.identity\0v1\0") || context.len() < 76 {
        return Err(PublicationError::Integrity);
    }
    let actual = Sha256::digest(context)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if actual != id {
        return Err(PublicationError::Integrity);
    }
    let tail = &context[context.len() - 76..];
    let size = u64::from_be_bytes(
        tail[..8]
            .try_into()
            .map_err(|_| PublicationError::Integrity)?,
    );
    let hash: [u8; 32] = tail[8..40]
        .try_into()
        .map_err(|_| PublicationError::Integrity)?;
    let actual_policy = u32::from_be_bytes(
        tail[72..76]
            .try_into()
            .map_err(|_| PublicationError::Integrity)?,
    );
    if size == 0 || actual_policy != policy {
        return Err(PublicationError::Integrity);
    }
    Ok((size, hash))
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
#[cfg(all(test, target_os = "linux"))]
mod publication_tests {
    use super::*;
    use crate::metadata::MetadataDb;
    use crate::publication::{FailurePoint, PublicationOutcome, publish_for_test};
    use sha2::{Digest, Sha256};
    use std::{io::Cursor, os::unix::fs::PermissionsExt};
    fn setup() -> (tempfile::TempDir, MetadataDb, StoreIdentity) {
        let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = MetadataDb::open(dir.path()).unwrap();
        let bytes = b"verified fixture";
        let material = IdentityMaterial {
            name: "sample".into(),
            version: "1".into(),
            architecture: "amd64".into(),
            distribution: "debian".into(),
            suite: "bookworm".into(),
            uri: "https://example.org/debian".into(),
            source_architecture: "amd64".into(),
            components: vec!["main".into()],
            fingerprints: vec!["012345".into()],
            artifact_path: "pool/main/s/sample.deb".into(),
            artifact_size: bytes.len() as u64,
            artifact_sha256: Sha256::digest(bytes).into(),
            release_sha256: [2; 32],
            policy: 2,
        };
        (dir, db, identity_from_material(material).unwrap())
    }
    #[test]
    fn publish_is_atomic_and_exact_reuse_checks_existing_bytes() {
        let (dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        assert_eq!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                Sha256::digest(bytes).into(),
                FailurePoint::None
            )
            .unwrap(),
            PublicationOutcome::Published
        );
        assert_eq!(
            std::fs::read(
                dir.path()
                    .join("objects")
                    .join(format!("{}.deb", identity.hex()))
            )
            .unwrap(),
            bytes
        );
        assert_eq!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                Sha256::digest(bytes).into(),
                FailurePoint::None
            )
            .unwrap(),
            PublicationOutcome::Reused
        );
    }
    #[test]
    fn failed_publication_never_commits_missing_object() {
        for point in [
            FailurePoint::BeforeFileSync,
            FailurePoint::AfterFileSync,
            FailurePoint::AfterRename,
            FailurePoint::AfterDirectorySync,
            FailurePoint::BeforeCommit,
        ] {
            let (_dir, mut db, identity) = setup();
            let bytes = b"verified fixture";
            assert!(
                publish_for_test(
                    &mut db,
                    &identity,
                    Cursor::new(bytes),
                    bytes.len() as u64,
                    Sha256::digest(bytes).into(),
                    point
                )
                .is_err()
            );
            assert_eq!(db.test_object_count(), 0);
            assert!(
                publish_for_test(
                    &mut db,
                    &identity,
                    Cursor::new(bytes),
                    bytes.len() as u64,
                    Sha256::digest(bytes).into(),
                    FailurePoint::None
                )
                .is_ok()
            );
            assert_eq!(db.test_object_count(), 1);
        }
    }
    #[test]
    fn adopting_orphan_requires_directory_sync_before_commit() {
        let (_dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        let hash = Sha256::digest(bytes).into();
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::AfterRename
            )
            .is_err()
        );
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::AfterDirectorySync
            )
            .is_err()
        );
        assert_eq!(db.test_object_count(), 0);
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None
            )
            .is_ok()
        );
    }
    #[test]
    fn failure_after_commit_is_recoverable_by_exact_retry() {
        let (dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        let hash = Sha256::digest(bytes).into();
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::AfterCommit
            )
            .is_err()
        );
        assert_eq!(db.test_object_count(), 1);
        drop(db);
        let mut db = MetadataDb::open(dir.path()).unwrap();
        assert_eq!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None
            )
            .unwrap(),
            PublicationOutcome::Reused
        );
    }
    #[test]
    fn altered_or_missing_published_content_is_never_silently_reused() {
        for remove in [false, true] {
            let (dir, mut db, identity) = setup();
            let bytes = b"verified fixture";
            let hash = Sha256::digest(bytes).into();
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None,
            )
            .unwrap();
            let path = dir
                .path()
                .join("objects")
                .join(format!("{}.deb", identity.hex()));
            if remove {
                std::fs::remove_file(&path).unwrap();
            } else {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::write(&path, b"tampered fixture").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            assert!(
                publish_for_test(
                    &mut db,
                    &identity,
                    Cursor::new(bytes),
                    bytes.len() as u64,
                    hash,
                    FailurePoint::None
                )
                .is_err()
            );
            assert_eq!(db.test_object_count(), 1);
        }
    }
    #[test]
    fn existing_symlink_and_digest_collision_fail_closed() {
        use std::os::unix::fs::symlink;
        let (dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        let hash = Sha256::digest(bytes).into();
        let target = dir.path().join("sentinel");
        std::fs::write(&target, b"do not change").unwrap();
        let objects = dir.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = objects.join(format!("{}.deb", identity.hex()));
        symlink(&target, &path).unwrap();
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"do not change");
        std::fs::remove_file(&path).unwrap();
        publish_for_test(
            &mut db,
            &identity,
            Cursor::new(bytes),
            bytes.len() as u64,
            hash,
            FailurePoint::None,
        )
        .unwrap();
        let mut different = StoreIdentity {
            digest: identity.digest,
            canonical: identity.canonical.clone(),
        };
        different.canonical.push(0);
        assert!(matches!(
            publish_for_test(
                &mut db,
                &different,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None
            ),
            Err(crate::publication::PublicationError::Collision)
        ));
    }
    #[test]
    #[ignore = "subprocess crash helper"]
    fn child_exits_at_publication_boundary() {
        let root = std::env::var_os("DICH_PUBLICATION_TEST_DIR").unwrap();
        let point = match std::env::var("DICH_PUBLICATION_FAILPOINT")
            .unwrap()
            .as_str()
        {
            "before_file_sync" => FailurePoint::BeforeFileSync,
            "after_file_sync" => FailurePoint::AfterFileSync,
            "after_rename" => FailurePoint::AfterRename,
            "after_directory_sync" => FailurePoint::AfterDirectorySync,
            "before_commit" => FailurePoint::BeforeCommit,
            "after_commit" => FailurePoint::AfterCommit,
            _ => panic!("unknown test failpoint"),
        };
        let mut db = MetadataDb::open(std::path::Path::new(&root)).unwrap();
        let bytes = b"verified fixture";
        let material = IdentityMaterial {
            name: "sample".into(),
            version: "1".into(),
            architecture: "amd64".into(),
            distribution: "debian".into(),
            suite: "bookworm".into(),
            uri: "https://example.org/debian".into(),
            source_architecture: "amd64".into(),
            components: vec!["main".into()],
            fingerprints: vec!["012345".into()],
            artifact_path: "pool/main/s/sample.deb".into(),
            artifact_size: bytes.len() as u64,
            artifact_sha256: Sha256::digest(bytes).into(),
            release_sha256: [2; 32],
            policy: 2,
        };
        let identity = identity_from_material(material).unwrap();
        let _ = publish_for_test(
            &mut db,
            &identity,
            Cursor::new(bytes),
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
            point,
        );
        panic!("test failpoint did not terminate process");
    }
    #[test]
    fn abrupt_process_exit_at_each_publication_boundary_is_retriable() {
        for point in [
            "before_file_sync",
            "after_file_sync",
            "after_rename",
            "after_directory_sync",
            "before_commit",
            "after_commit",
        ] {
            let (dir, db, identity) = setup();
            drop(db);
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "publication_tests::child_exits_at_publication_boundary",
                ])
                .env("DICH_PUBLICATION_TEST_DIR", dir.path())
                .env("DICH_PUBLICATION_FAILPOINT", point)
                .env("DICH_INJECT_PROCESS_EXIT", "1")
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(86),
                "{point}: {}",
                String::from_utf8_lossy(&child.stderr)
            );
            let mut reopened = MetadataDb::open(dir.path()).unwrap();
            assert_eq!(
                reopened.test_object_count(),
                if point == "after_commit" { 1 } else { 0 }
            );
            let bytes = b"verified fixture";
            assert!(
                publish_for_test(
                    &mut reopened,
                    &identity,
                    Cursor::new(bytes),
                    bytes.len() as u64,
                    Sha256::digest(bytes).into(),
                    FailurePoint::None
                )
                .is_ok()
            );
            assert_eq!(reopened.test_object_count(), 1);
        }
    }
    #[test]
    fn reuse_rejects_dangerous_mode_bits_on_existing_object() {
        let (dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        let hash = Sha256::digest(bytes).into();
        publish_for_test(
            &mut db,
            &identity,
            Cursor::new(bytes),
            bytes.len() as u64,
            hash,
            FailurePoint::None,
        )
        .unwrap();
        let path = dir
            .path()
            .join("objects")
            .join(format!("{}.deb", identity.hex()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4400)).unwrap();
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None
            )
            .is_err()
        );
    }
    #[test]
    fn existing_hardlink_is_never_adopted() {
        let (dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        let hash = Sha256::digest(bytes).into();
        let target = dir.path().join("protected");
        std::fs::write(&target, bytes).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();
        let objects = dir.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::hard_link(&target, objects.join(format!("{}.deb", identity.hex()))).unwrap();
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None
            )
            .is_err()
        );
        assert_eq!(std::fs::read(target).unwrap(), bytes);
        assert_eq!(db.test_object_count(), 0);
    }
    #[test]
    fn failed_source_revalidation_never_commits_publication() {
        let (_dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        let hash = Sha256::digest(bytes).into();
        let result = crate::publication::publish_reader(
            &mut db,
            &identity,
            Cursor::new(bytes),
            bytes.len() as u64,
            hash,
            FailurePoint::None,
            || Err(crate::publication::PublicationError::Authentication),
        );
        assert!(matches!(
            result,
            Err(crate::publication::PublicationError::Authentication)
        ));
        assert_eq!(db.test_object_count(), 0);
        assert!(
            publish_for_test(
                &mut db,
                &identity,
                Cursor::new(bytes),
                bytes.len() as u64,
                hash,
                FailurePoint::None
            )
            .is_ok()
        );
    }
    #[test]
    fn archive_verification_rechecks_bytes_and_local_identity() {
        let (dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        let id = identity.hex();
        assert!(db.verify_archive_object(&id).is_err());
        publish_for_test(
            &mut db,
            &identity,
            Cursor::new(bytes),
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
            FailurePoint::None,
        )
        .unwrap();
        assert_eq!(
            db.verify_archive_object(&id).unwrap().total_bytes,
            bytes.len() as u64
        );
        let path = dir.path().join("objects").join(format!("{id}.deb"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"tampered fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(db.verify_archive_object(&id).is_err());
        assert!(db.verify_archive_object("../bad").is_err());
    }
    #[test]
    fn archive_verification_rejects_mismatched_recorded_digest() {
        let (_dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        publish_for_test(
            &mut db,
            &identity,
            Cursor::new(bytes),
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
            FailurePoint::None,
        )
        .unwrap();
        let id = identity.hex();
        db.connection
            .execute(
                "UPDATE verified_archives SET artifact_sha256 = ?1 WHERE object_id = ?2",
                rusqlite::params![[0u8; 32].as_slice(), id],
            )
            .unwrap();
        assert!(db.verify_archive_object(&identity.hex()).is_err());
    }
    #[test]
    fn inspection_reports_archive_metadata_without_verifying_content() {
        let (dir, mut db, identity) = setup();
        let bytes = b"verified fixture";
        publish_for_test(
            &mut db,
            &identity,
            Cursor::new(bytes),
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
            FailurePoint::None,
        )
        .unwrap();
        let id = identity.hex();
        let records = db.list_objects().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, crate::ObjectKind::Archive);
        assert_eq!(
            db.inspect_object(&id, crate::ObjectKind::Archive).unwrap(),
            records[0]
        );
        std::fs::remove_file(dir.path().join("objects").join(format!("{id}.deb"))).unwrap();
        assert_eq!(db.list_objects().unwrap(), records);
        assert!(db.verify_archive_object(&id).is_err());
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tree_tests {
    use super::*;
    use crate::metadata::MetadataDb;
    use crate::publication::{FailurePoint, PublicationError};
    use crate::tree::{TreeInput, TreeOutcome, publish_tree_for_test};
    use sha2::{Digest, Sha256};
    use std::{io::Read, os::unix::fs::PermissionsExt};
    struct FixtureTree {
        root: tempfile::TempDir,
        directories: Vec<String>,
        files: Vec<dich_deb::StagedFile>,
    }
    impl TreeInput for FixtureTree {
        fn directories(&self) -> &[String] {
            &self.directories
        }
        fn files(&self) -> &[dich_deb::StagedFile] {
            &self.files
        }
        fn open(&self, path: &str) -> Result<Box<dyn Read>, PublicationError> {
            Ok(Box::new(
                std::fs::File::open(self.root.path().join(path))
                    .map_err(|_| PublicationError::Io)?,
            ))
        }
    }
    fn fixture() -> (tempfile::TempDir, MetadataDb, StoreIdentity, FixtureTree) {
        let root = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = MetadataDb::open(root.path()).unwrap();
        let stage = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        std::fs::create_dir(stage.path().join("usr")).unwrap();
        std::fs::write(stage.path().join("usr/file"), b"hello").unwrap();
        let file_hash = Sha256::digest(b"hello")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let stage = FixtureTree {
            root: stage,
            directories: vec!["usr".into()],
            files: vec![dich_deb::StagedFile {
                path: "usr/file".into(),
                size: 5,
                sha256: file_hash,
            }],
        };
        let material = IdentityMaterial {
            name: "sample".into(),
            version: "1".into(),
            architecture: "amd64".into(),
            distribution: "debian".into(),
            suite: "bookworm".into(),
            uri: "https://example.org/debian".into(),
            source_architecture: "amd64".into(),
            components: vec!["main".into()],
            fingerprints: vec!["012345".into()],
            artifact_path: "pool/main/s/sample.deb".into(),
            artifact_size: 42,
            artifact_sha256: [1; 32],
            release_sha256: [2; 32],
            policy: 1,
        };
        (root, db, identity_from_material(material).unwrap(), stage)
    }
    #[test]
    fn publishes_tree_and_verifies_all_bytes_before_reuse() {
        let (root, mut db, identity, stage) = fixture();
        assert_eq!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap(),
            TreeOutcome::Published
        );
        let path = root
            .path()
            .join("objects")
            .join(format!("{}.tree/usr/file", identity.hex()));
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert_eq!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap(),
            TreeOutcome::Reused
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"wrong").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_err());
    }
    #[test]
    fn changed_staging_bytes_do_not_create_a_committed_tree() {
        let (_root, mut db, identity, stage) = fixture();
        std::fs::write(stage.root.path().join("usr/file"), b"wrong").unwrap();
        assert!(publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_err());
        assert_eq!(db.test_tree_count(), 0);
    }
    #[test]
    fn rejects_unexpected_entries_and_links() {
        use std::os::unix::fs::symlink;
        for kind in ["extra", "symlink", "hardlink", "missing"] {
            let (root, mut db, identity, stage) = fixture();
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
            let tree = root
                .path()
                .join("objects")
                .join(format!("{}.tree/usr", identity.hex()));
            let file = tree.join("file");
            match kind {
                "extra" => std::fs::write(tree.join("extra"), b"x").unwrap(),
                "symlink" => {
                    std::fs::remove_file(&file).unwrap();
                    symlink(stage.root.path().join("usr/file"), &file).unwrap();
                }
                "hardlink" => {
                    std::fs::remove_file(&file).unwrap();
                    let target = stage.root.path().join("usr/file");
                    std::fs::hard_link(target, &file).unwrap();
                }
                "missing" => std::fs::remove_file(&file).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_err(),
                "{kind}"
            );
        }
    }
    #[test]
    fn rejects_invalid_manifests_before_publication() {
        for bad in [
            "../escape",
            "/absolute",
            "usr/../bad",
            "missing/file",
            "usr//bad",
        ] {
            let (_root, mut db, identity, mut stage) = fixture();
            stage.files[0].path = bad.into();
            assert!(
                publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_err(),
                "{bad}"
            );
            assert_eq!(db.test_tree_count(), 0);
        }
    }
    #[test]
    fn interrupted_publication_recovers_or_reuses_verified_tree() {
        for point in [
            FailurePoint::BeforeFileSync,
            FailurePoint::AfterFileSync,
            FailurePoint::AfterRename,
            FailurePoint::AfterDirectorySync,
            FailurePoint::BeforeCommit,
            FailurePoint::AfterCommit,
        ] {
            let (_root, mut db, identity, stage) = fixture();
            assert!(publish_tree_for_test(&mut db, &identity, &stage, point).is_err());
            let outcome =
                publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
            assert!(matches!(
                outcome,
                TreeOutcome::Published | TreeOutcome::Reused
            ));
            assert_eq!(db.test_tree_count(), 1);
        }
    }
    #[test]
    #[ignore = "subprocess crash helper"]
    fn tree_child_exits_at_boundary() {
        let target = match std::env::var_os("DICH_TREE_CRASH_ROOT") {
            Some(v) => v,
            None => return,
        };
        let point = match std::env::var("DICH_TREE_CRASH_POINT").unwrap().as_str() {
            "before_file" => FailurePoint::BeforeFileSync,
            "after_file" => FailurePoint::AfterFileSync,
            "after_rename" => FailurePoint::AfterRename,
            "after_dirs" => FailurePoint::AfterDirectorySync,
            "before_commit" => FailurePoint::BeforeCommit,
            "after_commit" => FailurePoint::AfterCommit,
            _ => panic!("invalid test point"),
        };
        let (_fixture_root, _fixture_db, identity, stage) = fixture();
        let mut db = MetadataDb::open(std::path::Path::new(&target)).unwrap();
        let _ = publish_tree_for_test(&mut db, &identity, &stage, point);
        panic!("injected process exit did not occur");
    }
    #[test]
    fn abrupt_tree_publication_exit_can_be_retried() {
        for point in [
            "before_file",
            "after_file",
            "after_rename",
            "after_dirs",
            "before_commit",
            "after_commit",
        ] {
            let (root, db, identity, stage) = fixture();
            drop(db);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "tree_tests::tree_child_exits_at_boundary",
                ])
                .env("DICH_TREE_CRASH_ROOT", root.path())
                .env("DICH_TREE_CRASH_POINT", point)
                .env("DICH_INJECT_PROCESS_EXIT", "1")
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86), "{point}");
            let mut db = MetadataDb::open(root.path()).unwrap();
            assert!(
                publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_ok(),
                "{point}"
            );
            assert_eq!(db.test_tree_count(), 1);
        }
    }
    #[test]
    fn recovery_inventory_reports_staging_and_orphans_without_deleting() {
        let (root, mut db, identity, stage) = fixture();
        assert!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::AfterRename).is_err()
        );
        let inventory = db.recovery_inventory().unwrap();
        assert_eq!(inventory.orphan_trees, vec![identity.hex()]);
        assert!(inventory.staged.is_empty());
        assert!(
            root.path()
                .join("objects")
                .join(format!("{}.tree", identity.hex()))
                .exists()
        );
        assert!(publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_ok());
        assert!(db.recovery_inventory().unwrap().orphan_trees.is_empty());
        let (_root2, mut db2, identity2, stage2) = fixture();
        assert!(
            publish_tree_for_test(&mut db2, &identity2, &stage2, FailurePoint::BeforeFileSync)
                .is_err()
        );
        assert_eq!(db2.recovery_inventory().unwrap().staged.len(), 1);
    }
    #[test]
    fn inventory_reports_missing_and_unknown_entries_without_following_links() {
        use std::os::unix::fs::symlink;
        let (root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let objects = root.path().join("objects");
        std::fs::rename(
            objects.join(format!("{}.tree", identity.hex())),
            objects.join("unrecognized"),
        )
        .unwrap();
        symlink(
            stage.root.path(),
            objects.join(format!("{}.tree", identity.hex())),
        )
        .unwrap();
        let report = db.recovery_inventory().unwrap();
        assert_eq!(report.missing_trees, vec![identity.hex()]);
        assert_eq!(report.unexpected.len(), 2);
        assert!(stage.root.path().join("usr/file").exists());
    }
    #[test]
    fn explicit_staging_cleanup_is_confined_and_retriable() {
        let (root, mut db, identity, stage) = fixture();
        assert!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::BeforeFileSync)
                .is_err()
        );
        let name = db.recovery_inventory().unwrap().staged.remove(0);
        db.remove_staged(&name).unwrap();
        assert!(db.recovery_inventory().unwrap().staged.is_empty());
        assert!(db.remove_staged("../outside").is_err());
        assert!(root.path().join("metadata.sqlite3").exists());
    }
    #[test]
    fn staging_cleanup_refuses_symlink_escape() {
        use std::os::unix::fs::symlink;
        let (root, mut db, identity, stage) = fixture();
        assert!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::BeforeFileSync)
                .is_err()
        );
        let name = db.recovery_inventory().unwrap().staged.remove(0);
        let staged = root.path().join("staging").join(&name);
        symlink(stage.root.path(), staged.join("escape")).unwrap();
        assert!(db.remove_staged(&name).is_err());
        assert!(stage.root.path().join("usr/file").exists());
    }
    #[test]
    #[ignore = "subprocess cleanup crash helper"]
    fn cleanup_child_exits_after_unlink() {
        let Some(root) = std::env::var_os("DICH_CLEANUP_ROOT") else {
            return;
        };
        let name = std::env::var("DICH_CLEANUP_NAME").unwrap();
        let mut db = MetadataDb::open(std::path::Path::new(&root)).unwrap();
        let _ = db.remove_staged(&name);
        panic!("injected cleanup exit did not occur");
    }
    #[test]
    fn interrupted_cleanup_can_be_retried() {
        let (root, mut db, identity, stage) = fixture();
        assert!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::BeforeFileSync)
                .is_err()
        );
        let name = db.recovery_inventory().unwrap().staged.remove(0);
        drop(db);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "tree_tests::cleanup_child_exits_after_unlink",
            ])
            .env("DICH_CLEANUP_ROOT", root.path())
            .env("DICH_CLEANUP_NAME", &name)
            .env("DICH_INJECT_CLEANUP_EXIT", "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(87));
        let mut db = MetadataDb::open(root.path()).unwrap();
        db.remove_staged(&name).unwrap();
        assert!(db.recovery_inventory().unwrap().staged.is_empty());
    }
    #[test]
    fn orphan_cleanup_refuses_committed_objects_and_removes_only_unreferenced() {
        let (_root, mut db, identity, stage) = fixture();
        assert!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::AfterRename).is_err()
        );
        assert_eq!(
            db.recovery_inventory().unwrap().orphan_trees,
            vec![identity.hex()]
        );
        db.remove_orphan(&identity.hex(), crate::OrphanKind::Tree)
            .unwrap();
        assert!(db.recovery_inventory().unwrap().orphan_trees.is_empty());
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        assert!(
            db.remove_orphan(&identity.hex(), crate::OrphanKind::Tree)
                .is_err()
        );
        assert!(publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_ok());
        assert!(
            db.remove_orphan("../invalid", crate::OrphanKind::Tree)
                .is_err()
        );
    }
    #[test]
    fn orphan_cleanup_refuses_symlinks_and_hardlinked_archives() {
        use std::os::unix::fs::symlink;
        let (root, mut db, identity, stage) = fixture();
        std::fs::create_dir(root.path().join("objects")).unwrap();
        std::fs::set_permissions(
            root.path().join("objects"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let target = stage.root.path().join("usr/file");
        let link = root
            .path()
            .join("objects")
            .join(format!("{}.tree", identity.hex()));
        symlink(stage.root.path(), &link).unwrap();
        assert!(
            db.remove_orphan(&identity.hex(), crate::OrphanKind::Tree)
                .is_err()
        );
        let archive = root
            .path()
            .join("objects")
            .join(format!("{}.deb", identity.hex()));
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::hard_link(&target, archive).unwrap();
        assert!(
            db.remove_orphan(&identity.hex(), crate::OrphanKind::Archive)
                .is_err()
        );
        assert_eq!(std::fs::read(target).unwrap(), b"hello");
    }
    #[test]
    fn tree_authentication_failure_leaves_only_unreferenced_object() {
        let (_root, mut db, identity, stage) = fixture();
        let error =
            crate::tree::publish_tree(&mut db, &identity, &stage, FailurePoint::None, || {
                Err(PublicationError::Authentication)
            });
        assert!(matches!(error, Err(PublicationError::Authentication)));
        assert_eq!(db.test_tree_count(), 0);
        assert_eq!(
            db.recovery_inventory().unwrap().orphan_trees,
            vec![identity.hex()]
        );
        assert!(publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).is_ok());
    }
    #[test]
    fn same_identity_with_changed_tree_manifest_fails_closed() {
        let (_root, mut db, identity, mut stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        stage.files[0].sha256 = "00".repeat(32);
        assert!(matches!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None),
            Err(PublicationError::Collision)
        ));
    }
    #[test]
    fn inventory_rejects_special_bits_on_private_directories() {
        for name in ["objects", "staging"] {
            let (root, db, _identity, _stage) = fixture();
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o2700)).unwrap();
            assert!(db.recovery_inventory().is_err(), "{name}");
        }
    }
    #[test]
    fn graph_snapshots_require_committed_nodes_and_survive_reopen() {
        use dich_core::reference_graph::ReferenceGraph;
        let (root, mut db, identity, stage) = fixture();
        let id = identity.hex();
        let graph = ReferenceGraph::new(&[&id], &[]).unwrap();
        assert!(db.put_reference_graph(&graph).is_err());
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let (graph_id, outcome) = db.put_reference_graph(&graph).unwrap();
        assert_eq!(outcome, crate::GraphOutcome::Published);
        assert_eq!(
            db.put_reference_graph(&graph).unwrap().1,
            crate::GraphOutcome::Reused
        );
        drop(db);
        let mut db = MetadataDb::open(root.path()).unwrap();
        assert_eq!(
            db.put_reference_graph(&graph).unwrap(),
            (graph_id, crate::GraphOutcome::Reused)
        );
    }
    #[test]
    fn graph_snapshot_rejects_uncommitted_dependency() {
        use dich_core::reference_graph::ReferenceGraph;
        let (_root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let root = identity.hex();
        let missing = "f".repeat(64);
        let graph = ReferenceGraph::new(&[&root], &[(&root, &missing)]).unwrap();
        assert!(db.put_reference_graph(&graph).is_err());
        assert_eq!(db.test_graph_count(), 0);
    }
    #[test]
    fn graph_transaction_rolls_back_and_detects_corrupt_members_and_collisions() {
        use dich_core::reference_graph::ReferenceGraph;
        let (_root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let id = identity.hex();
        let graph = ReferenceGraph::new(&[&id], &[]).unwrap();
        assert!(crate::graph::put_graph(&mut db, &graph, FailurePoint::BeforeCommit).is_err());
        assert_eq!(db.test_graph_count(), 0);
        let (graph_id, _) = db.put_reference_graph(&graph).unwrap();
        db.connection
            .execute(
                "DELETE FROM reference_members WHERE graph_id = ?1",
                [&graph_id],
            )
            .unwrap();
        assert!(matches!(
            db.put_reference_graph(&graph),
            Err(PublicationError::Integrity)
        ));
        db.connection
            .execute(
                "UPDATE reference_graphs SET manifest = ?1 WHERE graph_id = ?2",
                rusqlite::params![b"forged".as_slice(), graph_id],
            )
            .unwrap();
        assert!(matches!(
            db.put_reference_graph(&graph),
            Err(PublicationError::Collision)
        ));
    }
    #[test]
    #[ignore = "subprocess graph transaction crash helper"]
    fn graph_child_exits_at_commit_boundary() {
        use dich_core::reference_graph::ReferenceGraph;
        let Some(root) = std::env::var_os("DICH_GRAPH_CRASH_ROOT") else {
            return;
        };
        let point = match std::env::var("DICH_GRAPH_CRASH_POINT").unwrap().as_str() {
            "before" => FailurePoint::BeforeCommit,
            "after" => FailurePoint::AfterCommit,
            _ => panic!("invalid test point"),
        };
        let (_fixture_root, _fixture_db, identity, _stage) = fixture();
        let id = identity.hex();
        let graph = ReferenceGraph::new(&[&id], &[]).unwrap();
        let mut db = MetadataDb::open(std::path::Path::new(&root)).unwrap();
        let _ = crate::graph::put_graph(&mut db, &graph, point);
        panic!("expected injected graph exit");
    }
    #[test]
    fn graph_recovers_after_abrupt_exit_at_commit() {
        use dich_core::reference_graph::ReferenceGraph;
        for point in ["before", "after"] {
            let (root, mut db, identity, stage) = fixture();
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
            let id = identity.hex();
            let graph = ReferenceGraph::new(&[&id], &[]).unwrap();
            drop(db);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "tree_tests::graph_child_exits_at_commit_boundary",
                ])
                .env("DICH_GRAPH_CRASH_ROOT", root.path())
                .env("DICH_GRAPH_CRASH_POINT", point)
                .env("DICH_INJECT_PROCESS_EXIT", "1")
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86));
            let mut db = MetadataDb::open(root.path()).unwrap();
            assert_eq!(db.test_graph_count(), i64::from(point == "after"));
            let (_, outcome) = db.put_reference_graph(&graph).unwrap();
            assert_eq!(
                outcome,
                if point == "after" {
                    crate::GraphOutcome::Reused
                } else {
                    crate::GraphOutcome::Published
                }
            );
            assert_eq!(db.test_graph_count(), 1);
        }
    }
    #[test]
    fn graph_stores_dependency_members_and_foreign_keys_prevent_deletion() {
        use dich_core::reference_graph::ReferenceGraph;
        let (_root, mut db, identity, stage) = fixture();
        let (_unused_root, _unused_db, mut other, _unused_stage) = fixture();
        let position = b"dich.store.identity\0v1\0".len() + 4;
        other.canonical[position] ^= 1;
        other.digest = Sha256::digest(&other.canonical).into();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        publish_tree_for_test(&mut db, &other, &stage, FailurePoint::None).unwrap();
        let (a, b) = (identity.hex(), other.hex());
        let graph = ReferenceGraph::new(&[&a], &[(&a, &b)]).unwrap();
        let (graph_id, _) = db.put_reference_graph(&graph).unwrap();
        let count: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM reference_members WHERE graph_id = ?1",
                [&graph_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
        assert!(
            db.connection
                .execute("DELETE FROM verified_trees WHERE object_id = ?1", [&b])
                .is_err()
        );
    }
    #[test]
    fn orphan_cleanup_refuses_even_dangling_graph_references() {
        let (root, mut db, identity, stage) = fixture();
        assert!(
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::AfterRename).is_err()
        );
        let id = identity.hex();
        db.connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .unwrap();
        db.connection
            .execute(
                "INSERT INTO reference_graphs VALUES (?1, ?2)",
                rusqlite::params!["f".repeat(64), b"bad".as_slice()],
            )
            .unwrap();
        db.connection
            .execute(
                "INSERT INTO reference_members VALUES (?1, ?2)",
                rusqlite::params!["f".repeat(64), id],
            )
            .unwrap();
        db.connection
            .execute_batch("PRAGMA foreign_keys = ON")
            .unwrap();
        assert!(
            db.remove_orphan(&identity.hex(), crate::OrphanKind::Tree)
                .is_err()
        );
        assert!(
            root.path()
                .join("objects")
                .join(format!("{}.tree", identity.hex()))
                .exists()
        );
    }
    #[test]
    fn tree_verification_checks_persisted_manifest_and_detects_mutation() {
        let (root, mut db, identity, stage) = fixture();
        let id = identity.hex();
        assert!(db.verify_tree_object(&id).is_err());
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let report = db.verify_tree_object(&id).unwrap();
        assert_eq!(report.files, 1);
        assert_eq!(report.total_bytes, 5);
        let path = root
            .path()
            .join("objects")
            .join(format!("{id}.tree/usr/file"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"wrong").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(db.verify_tree_object(&id).is_err());
        assert!(db.verify_tree_object("../bad").is_err());
    }
    #[test]
    fn tree_verification_rejects_corrupt_metadata_and_extra_files() {
        let (root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let id = identity.hex();
        let tree = root.path().join("objects").join(format!("{id}.tree"));
        std::fs::write(tree.join("extra"), b"x").unwrap();
        assert!(db.verify_tree_object(&id).is_err());
        std::fs::remove_file(tree.join("extra")).unwrap();
        db.connection
            .execute(
                "UPDATE verified_trees SET tree_manifest = ?1 WHERE object_id = ?2",
                rusqlite::params![b"invalid".as_slice(), id],
            )
            .unwrap();
        assert!(db.verify_tree_object(&identity.hex()).is_err());
    }
    #[test]
    fn tree_verification_rejects_truncated_oversized_and_noncanonical_manifests() {
        for variant in ["truncated", "trailing", "count", "path"] {
            let (_root, mut db, identity, stage) = fixture();
            publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
            let id = identity.hex();
            let mut encoded: Vec<u8> = db
                .connection
                .query_row(
                    "SELECT tree_manifest FROM verified_trees WHERE object_id = ?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            match variant {
                "truncated" => {
                    encoded.pop();
                }
                "trailing" => encoded.push(0),
                "count" => {
                    let offset = b"dich.tree.manifest\0v1\0".len();
                    encoded[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
                }
                "path" => {
                    let offset = b"dich.tree.manifest\0v1\0".len() + 8;
                    encoded[offset..offset + 3].copy_from_slice(b"../");
                }
                _ => unreachable!(),
            }
            db.connection
                .execute(
                    "UPDATE verified_trees SET tree_manifest = ?1 WHERE object_id = ?2",
                    rusqlite::params![encoded, id],
                )
                .unwrap();
            assert!(db.verify_tree_object(&identity.hex()).is_err(), "{variant}");
        }
    }
    #[test]
    fn inspect_lists_committed_objects_without_claiming_content_verified() {
        let (root, mut db, identity, stage) = fixture();
        assert!(db.list_objects().unwrap().is_empty());
        assert!(!root.path().join("objects").exists());
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let records = db.list_objects().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, identity.hex());
        assert_eq!(records[0].kind, crate::ObjectKind::Tree);
        assert_eq!(records[0].stored_bytes, 5);
        assert_eq!(
            db.inspect_object(&identity.hex(), crate::ObjectKind::Tree)
                .unwrap(),
            records[0]
        );
        assert!(
            db.inspect_object(&identity.hex(), crate::ObjectKind::Archive)
                .is_err()
        );
        assert!(
            db.inspect_object("../bad", crate::ObjectKind::Tree)
                .is_err()
        );
    }
    #[test]
    fn inspect_rejects_inconsistent_identity_metadata() {
        let (_root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        db.connection
            .execute(
                "UPDATE verified_trees SET manifest = ?1 WHERE object_id = ?2",
                rusqlite::params![b"bad".as_slice(), identity.hex()],
            )
            .unwrap();
        assert!(db.list_objects().is_err());
        assert!(
            db.inspect_object(&identity.hex(), crate::ObjectKind::Tree)
                .is_err()
        );
    }
    #[test]
    fn inspection_remains_metadata_only_after_content_corruption() {
        let (root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let id = identity.hex();
        let path = root
            .path()
            .join("objects")
            .join(format!("{id}.tree/usr/file"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"wrong").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            db.inspect_object(&id, crate::ObjectKind::Tree)
                .unwrap()
                .stored_bytes,
            5
        );
        assert!(db.verify_tree_object(&id).is_err());
    }
    #[test]
    fn reference_graph_readback_checks_identity_and_membership() {
        use dich_core::reference_graph::ReferenceGraph;
        let (_root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let id = identity.hex();
        let graph = ReferenceGraph::new(&[&id], &[]).unwrap();
        let (graph_id, _) = db.put_reference_graph(&graph).unwrap();
        assert_eq!(db.read_reference_graph(&graph_id).unwrap(), graph);
        assert!(db.read_reference_graph("../bad").is_err());
        db.connection
            .execute(
                "DELETE FROM reference_members WHERE graph_id = ?1",
                [&graph_id],
            )
            .unwrap();
        assert!(db.read_reference_graph(&graph_id).is_err());
        db.connection
            .execute(
                "UPDATE reference_graphs SET manifest = ?1 WHERE graph_id = ?2",
                rusqlite::params![b"bad".as_slice(), graph_id],
            )
            .unwrap();
        assert!(db.read_reference_graph(&graph_id).is_err());
    }
    #[test]
    fn graph_creation_rejects_corrupt_tree_identity_metadata() {
        use dich_core::reference_graph::ReferenceGraph;
        let (_root, mut db, identity, stage) = fixture();
        publish_tree_for_test(&mut db, &identity, &stage, FailurePoint::None).unwrap();
        let id = identity.hex();
        db.connection
            .execute(
                "UPDATE verified_trees SET manifest = ?1 WHERE object_id = ?2",
                rusqlite::params![b"bad".as_slice(), id],
            )
            .unwrap();
        let graph = ReferenceGraph::new(&[&identity.hex()], &[]).unwrap();
        assert!(db.put_reference_graph(&graph).is_err());
        assert_eq!(db.test_graph_count(), 0);
    }
}
