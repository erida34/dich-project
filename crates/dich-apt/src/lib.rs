#![forbid(unsafe_code)]
//! Explicit source policy and conservative deb822 import; no repository data is authenticated yet.

mod config;
mod index;
mod keyring;
pub use index::{
    IndexError, IndexFormat, IndexLimits, VerifiedIndex, verify_packages_index,
    verify_packages_index_with_limits,
};
mod signatures;
pub use keyring::read_configured_keyring;
mod sources;
pub use config::{ConfiguredSource, parse_source_config, read_source_config};
pub use signatures::{
    SignatureError, VerifiedRelease, verify_configured_detached_release,
    verify_configured_inrelease,
};
pub use sources::{Distribution, Source, SourceError, SourcePolicy, import_sources};

#[cfg(all(test, target_os = "linux"))]
mod signature_tests;
