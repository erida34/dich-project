#![forbid(unsafe_code)]
//! Explicit source policy and conservative deb822 import; no repository data is authenticated yet.

mod config;
mod keyring;
mod signatures;
pub use keyring::read_configured_keyring;
mod sources;
pub use config::{ConfiguredSource, parse_source_config, read_source_config};
pub use signatures::{
    SignatureError, VerifiedRelease, verify_configured_detached_release,
    verify_configured_inrelease, verify_detached_release, verify_inrelease,
};
pub use sources::{Distribution, Source, SourceError, SourcePolicy, import_sources};
