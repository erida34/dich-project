use serde::Deserialize;
use std::io::Read;

use crate::{Distribution, SourceError, SourcePolicy, sources::safe_keyring};

/// Read operator policy and its source files through trusted filesystem paths.
#[cfg(target_os = "linux")]
pub fn load_configured_sources(path: &std::path::Path) -> Result<Vec<crate::Source>, SourceError> {
    let bytes =
        crate::keyring::read_trusted_file(path, MAX_CONFIG_SIZE).map_err(|_| SourceError::Io)?;
    let policies = read_source_config(bytes.as_slice())?;
    let mut sources = Vec::new();
    for config in policies {
        let input = crate::keyring::read_trusted_file(
            std::path::Path::new(config.sources_file()),
            MAX_CONFIG_SIZE,
        )
        .map_err(|_| SourceError::Io)?;
        let input =
            std::str::from_utf8(&input).map_err(|_| SourceError::Invalid("sources UTF-8"))?;
        sources.extend(crate::import_sources(input, config.policy())?);
    }
    Ok(sources)
}

#[cfg(not(target_os = "linux"))]
pub fn load_configured_sources(_: &std::path::Path) -> Result<Vec<crate::Source>, SourceError> {
    Err(SourceError::Unsupported(
        "trusted source loading requires Linux",
    ))
}

const MAX_CONFIG_SIZE: usize = 1024 * 1024;
const MAX_SOURCES: usize = 256;

/// A validated association between an operator policy and a deb822 file path.
/// This value does not open the file or authenticate any data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredSource {
    sources_file: String,
    policy: SourcePolicy,
}
impl ConfiguredSource {
    pub fn sources_file(&self) -> &str {
        &self.sources_file
    }
    pub fn policy(&self) -> &SourcePolicy {
        &self.policy
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    sources: Vec<RawSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    distribution: RawDistribution,
    sources_file: String,
    uri: String,
    suite: String,
    components: Vec<String>,
    architecture: String,
    keyring: String,
    fingerprints: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawDistribution {
    Debian,
    Ubuntu,
}

/// Read at most one MiB of UTF-8 TOML from a caller-controlled, already opened input.
/// The caller is responsible for choosing and securely opening a trusted file.
pub fn read_source_config(reader: impl Read) -> Result<Vec<ConfiguredSource>, SourceError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_CONFIG_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SourceError::Io)?;
    if bytes.len() > MAX_CONFIG_SIZE {
        return Err(SourceError::InputTooLarge);
    }
    let input = std::str::from_utf8(&bytes).map_err(|_| SourceError::Invalid("policy UTF-8"))?;
    parse_source_config(input)
}

/// Parse explicit TOML operator policy. Caller must load it from a trusted location.
pub fn parse_source_config(input: &str) -> Result<Vec<ConfiguredSource>, SourceError> {
    if input.len() > MAX_CONFIG_SIZE {
        return Err(SourceError::InputTooLarge);
    }
    let raw: RawConfig = toml::from_str(input).map_err(|_| SourceError::Invalid("policy TOML"))?;
    if raw.sources.is_empty() || raw.sources.len() > MAX_SOURCES {
        return Err(SourceError::Invalid("source count"));
    }
    let mut result: Vec<ConfiguredSource> = Vec::with_capacity(raw.sources.len());
    for source in raw.sources {
        if !safe_keyring(&source.sources_file) {
            return Err(SourceError::Invalid("sources file path"));
        }
        if result
            .iter()
            .any(|item| item.sources_file == source.sources_file)
        {
            return Err(SourceError::Invalid("duplicate sources file"));
        }
        let distribution = match source.distribution {
            RawDistribution::Debian => Distribution::Debian,
            RawDistribution::Ubuntu => Distribution::Ubuntu,
        };
        let components: Vec<&str> = source.components.iter().map(String::as_str).collect();
        let fingerprints: Vec<&str> = source.fingerprints.iter().map(String::as_str).collect();
        let policy = SourcePolicy::new(
            distribution,
            &source.uri,
            &source.suite,
            &components,
            &source.architecture,
            &source.keyring,
            &fingerprints,
        )?;
        result.push(ConfiguredSource {
            sources_file: source.sources_file,
            policy,
        });
    }
    Ok(result)
}
