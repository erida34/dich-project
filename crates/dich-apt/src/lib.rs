#![forbid(unsafe_code)]
//! Source policy, signed metadata verification and bounded parsing; package fetch remains incomplete.

mod artifact;
#[cfg(target_os = "linux")]
mod cache;
#[cfg(target_os = "linux")]
pub use cache::{CacheError, SnapshotJournal, SnapshotPin};
mod config;
pub use artifact::{
    ArtifactError, AuthorizedArtifact, IndexedArtifact, VerifiedArtifact, authorize_artifact,
    select_indexed_artifact,
};
mod control;
mod dependencies;
pub use control::{ControlError, ControlStanza, parse_control_stanzas};
pub use dependencies::{
    Comparison, DependencyError, DependencyGroup, DependencyRelation, VersionConstraint,
    parse_dependencies,
};
mod index;
mod keyring;
pub use index::{
    IndexError, IndexFormat, IndexLimits, VerifiedIndex, choose_index_format,
    verify_packages_index, verify_packages_index_with_limits,
};
mod signatures;
pub use keyring::read_configured_keyring;
mod freshness;
mod sources;
mod transport;
pub use transport::{FetchError, FetchedIndex, fetch_packages_index, fetch_signed_release};
#[cfg(target_os = "linux")]
mod update;
#[cfg(target_os = "linux")]
pub use update::{UpdateError, UpdateReport, update_source};
#[cfg(target_os = "linux")]
mod query;
#[cfg(target_os = "linux")]
pub use query::{PackageRecord, Query, QueryError, query_cached};
mod version;
pub use config::{
    ConfiguredSource, load_configured_sources, parse_source_config, read_source_config,
};
pub use freshness::{FreshnessError, FreshnessPolicy, ValidatedRelease, validate_release};
pub use signatures::{
    SignatureError, VerifiedRelease, verify_configured_detached_release,
    verify_configured_inrelease,
};
pub use sources::{Distribution, Source, SourceError, SourcePolicy, import_sources};
pub use version::{DebianVersion, VersionError};

#[cfg(all(test, target_os = "linux"))]
mod artifact_tests;
#[cfg(all(test, target_os = "linux"))]
mod cache_tests;
#[cfg(all(test, target_os = "linux"))]
mod signature_tests;
#[cfg(all(test, target_os = "linux"))]
mod transport_tests;
