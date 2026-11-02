use std::{collections::BTreeMap, error::Error, fmt};

const MAX_INPUT: usize = 1024 * 1024;
const MAX_STANZAS: usize = 256;
const MAX_FIELD: usize = 16 * 1024;
const MAX_VALUES: usize = 128;

/// Distribution identity is supplied by the operator, not inferred from a hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distribution {
    Debian,
    Ubuntu,
}

/// An input or operator policy error, not a repository authentication result.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceError {
    InputTooLarge,
    Io,
    Invalid(&'static str),
    Unsupported(&'static str),
    PolicyMismatch(&'static str),
}
impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("sources input exceeds the size limit"),
            Self::Io => f.write_str("failed to read source configuration"),
            Self::Invalid(s) => write!(f, "invalid source configuration: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported source configuration: {s}"),
            Self::PolicyMismatch(s) => write!(f, "source violates configured policy: {s}"),
        }
    }
}
impl Error for SourceError {}

/// An operator-provided allowlist independent of the imported file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePolicy {
    distribution: Distribution,
    uri: String,
    suite: String,
    components: Vec<String>,
    architecture: String,
    keyring: String,
    fingerprints: Vec<String>,
}

/// Parsed configuration only: key material and signatures have not been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source(SourcePolicy);
impl Source {
    pub fn distribution(&self) -> Distribution {
        self.0.distribution
    }
    pub fn uri(&self) -> &str {
        &self.0.uri
    }
    pub fn suite(&self) -> &str {
        &self.0.suite
    }
    pub fn components(&self) -> &[String] {
        &self.0.components
    }
    pub fn architecture(&self) -> &str {
        &self.0.architecture
    }
    pub fn keyring(&self) -> &str {
        &self.0.keyring
    }
    pub fn fingerprints(&self) -> &[String] {
        &self.0.fingerprints
    }
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+.-_".contains(&b))
        && s != "."
        && s != ".."
}
fn safe_uri(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    if s.len() > 2048 || !s.is_ascii() {
        return false;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = authority.split_once(':').unwrap_or((authority, ""));
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        || (authority.contains(':')
            && (port.is_empty() || port.parse::<u16>().ok().filter(|p| *p != 0).is_none()))
    {
        return false;
    }
    path.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
        && !path.split('/').any(|part| part == "." || part == "..")
        && !path.contains("//")
}
pub(crate) fn safe_keyring(s: &str) -> bool {
    s.len() <= 4096
        && s.starts_with('/')
        && !s.ends_with('/')
        && s.is_ascii()
        && s.split('/').skip(1).all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        })
}
fn fingerprint(s: &str) -> Option<String> {
    let digits = s.strip_suffix('!').unwrap_or(s);
    if !matches!(digits.len(), 40 | 64) || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(s.to_ascii_uppercase())
}
fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(i, value)| values[..i].contains(value))
}

impl SourcePolicy {
    pub fn new(
        distribution: Distribution,
        uri: &str,
        suite: &str,
        components: &[&str],
        architecture: &str,
        keyring: &str,
        fingerprints: &[&str],
    ) -> Result<Self, SourceError> {
        if !safe_uri(uri) {
            return Err(SourceError::Invalid("repository URI"));
        }
        if !identifier(suite)
            || !identifier(architecture)
            || components.is_empty()
            || components.len() > MAX_VALUES
            || components.iter().any(|c| !identifier(c))
        {
            return Err(SourceError::Invalid("suite, components or architecture"));
        }
        if !safe_keyring(keyring) {
            return Err(SourceError::Invalid("keyring path"));
        }
        if fingerprints.is_empty() || fingerprints.len() > MAX_VALUES {
            return Err(SourceError::Invalid("missing signing fingerprints"));
        }
        let fingerprints: Vec<String> = fingerprints
            .iter()
            .map(|s| fingerprint(s).ok_or(SourceError::Invalid("fingerprint")))
            .collect::<Result<_, _>>()?;
        let components: Vec<String> = components.iter().map(|s| (*s).to_owned()).collect();
        if has_duplicates(&components) || has_duplicates(&fingerprints) {
            return Err(SourceError::Invalid("duplicate policy value"));
        }
        Ok(Self {
            distribution,
            uri: uri.into(),
            suite: suite.into(),
            components,
            architecture: architecture.into(),
            keyring: keyring.into(),
            fingerprints,
        })
    }
}

/// Import a bounded deb822 file under an explicit operator policy.
pub fn import_sources(input: &str, policy: &SourcePolicy) -> Result<Vec<Source>, SourceError> {
    if input.len() > MAX_INPUT {
        return Err(SourceError::InputTooLarge);
    }
    if input
        .bytes()
        .any(|b| b == 0 || (b.is_ascii_control() && !matches!(b, b'\n' | b'\r' | b'\t')))
    {
        return Err(SourceError::Invalid("control character"));
    }
    let mut output = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut previous: Option<String> = None;
    let mut stanzas = 0usize;
    for line in input.lines().chain(std::iter::once("")) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() {
            if !fields.is_empty() {
                stanzas += 1;
                if stanzas > MAX_STANZAS {
                    return Err(SourceError::Invalid("too many stanzas"));
                }
                if let Some(source) = parse_stanza(&fields, policy)? {
                    output.push(source);
                }
                fields.clear();
            }
            previous = None;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let key = previous
                .as_ref()
                .ok_or(SourceError::Invalid("orphan continuation"))?;
            let value = fields
                .get_mut(key)
                .ok_or(SourceError::Invalid("orphan continuation"))?;
            if value.len().saturating_add(line.len()) > MAX_FIELD {
                return Err(SourceError::Invalid("field too large"));
            }
            value.push(' ');
            value.push_str(line.trim());
        } else {
            let (key, value) = line
                .split_once(':')
                .ok_or(SourceError::Invalid("field syntax"))?;
            if key.is_empty()
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || value.len() > MAX_FIELD
            {
                return Err(SourceError::Invalid("field syntax or size"));
            }
            let key = key.to_ascii_lowercase();
            if fields
                .insert(key.clone(), value.trim().to_owned())
                .is_some()
            {
                return Err(SourceError::Invalid("duplicate field"));
            }
            previous = Some(key);
        }
    }
    Ok(output)
}

fn parse_stanza(
    fields: &BTreeMap<String, String>,
    policy: &SourcePolicy,
) -> Result<Option<Source>, SourceError> {
    if let Some(enabled) = fields.get("enabled") {
        match enabled.as_str() {
            "no" => return Ok(None),
            "yes" => (),
            _ => return Err(SourceError::Invalid("Enabled")),
        }
    }
    for key in fields.keys() {
        if ![
            "types",
            "uris",
            "suites",
            "components",
            "architectures",
            "signed-by",
            "enabled",
        ]
        .contains(&key.as_str())
        {
            return Err(SourceError::Unsupported("source field"));
        }
    }
    let required = |name: &str| {
        fields
            .get(name)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(SourceError::Invalid("missing required field"))
    };
    if required("types")? != "deb" {
        return Err(SourceError::Unsupported("source type"));
    }
    if required("uris")? != policy.uri {
        return Err(SourceError::PolicyMismatch("URI"));
    }
    if required("suites")? != policy.suite {
        return Err(SourceError::PolicyMismatch("suite"));
    }
    let components: Vec<String> = required("components")?
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    if components.is_empty()
        || components.len() > MAX_VALUES
        || has_duplicates(&components)
        || components.iter().any(|c| !policy.components.contains(c))
    {
        return Err(SourceError::PolicyMismatch("components"));
    }
    if let Some(architecture) = fields.get("architectures") {
        if architecture != &policy.architecture {
            return Err(SourceError::PolicyMismatch("architecture"));
        }
    }
    let mut signed_by = required("signed-by")?.split_ascii_whitespace();
    if signed_by.next() != Some(policy.keyring.as_str()) {
        return Err(SourceError::PolicyMismatch("keyring"));
    }
    let fingerprints: Vec<String> = signed_by
        .map(|s| fingerprint(s).ok_or(SourceError::Invalid("fingerprint")))
        .collect::<Result<_, _>>()?;
    if fingerprints.len() > MAX_VALUES
        || has_duplicates(&fingerprints)
        || fingerprints
            .iter()
            .any(|f| !policy.fingerprints.contains(f))
    {
        return Err(SourceError::PolicyMismatch("fingerprint"));
    }
    let mut source = policy.clone();
    source.components = components;
    if !fingerprints.is_empty() {
        source.fingerprints = fingerprints;
    }
    Ok(Some(Source(source)))
}
