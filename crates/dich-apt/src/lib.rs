#![forbid(unsafe_code)]
//! Explicit source policy and conservative deb822 import; no repository data is authenticated yet.

mod sources;
pub use sources::{Distribution, Source, SourceError, SourcePolicy, import_sources};
