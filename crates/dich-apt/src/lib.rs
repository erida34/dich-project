#![forbid(unsafe_code)]
//! Explicit source policy and conservative deb822 import; no repository data is authenticated yet.

mod config;
mod sources;
pub use config::{ConfiguredSource, parse_source_config, read_source_config};
pub use sources::{Distribution, Source, SourceError, SourcePolicy, import_sources};
