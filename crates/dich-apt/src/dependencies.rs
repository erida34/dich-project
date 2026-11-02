//! Parsing Debian relationship expressions; evaluation is a separate resolver concern.
use crate::DebianVersion;
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Less,
    LessOrEqual,
    Equal,
    GreaterOrEqual,
    Greater,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionConstraint {
    operator: Comparison,
    version: DebianVersion,
}
impl VersionConstraint {
    pub fn operator(&self) -> Comparison {
        self.operator
    }
    pub fn version(&self) -> &DebianVersion {
        &self.version
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRelation {
    name: String,
    qualifier: Option<String>,
    version: Option<VersionConstraint>,
    architectures: Vec<String>,
    profiles: Vec<Vec<String>>,
}
impl DependencyRelation {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }
    pub fn version(&self) -> Option<&VersionConstraint> {
        self.version.as_ref()
    }
    pub fn architectures(&self) -> &[String] {
        &self.architectures
    }
    pub fn profiles(&self) -> &[Vec<String>] {
        &self.profiles
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyGroup {
    alternatives: Vec<DependencyRelation>,
}
impl DependencyGroup {
    pub fn alternatives(&self) -> &[DependencyRelation] {
        &self.alternatives
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyError;
impl fmt::Display for DependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or unsupported Debian dependency expression")
    }
}
impl Error for DependencyError {}

/// Parse comma-separated dependency groups with pipe-separated alternatives.
pub fn parse_dependencies(input: &str) -> Result<Vec<DependencyGroup>, DependencyError> {
    if input.is_empty() || input.len() > 1024 * 1024 || !input.is_ascii() {
        return Err(DependencyError);
    }
    let mut groups = Vec::new();
    for group in split_top(input, b',')? {
        if groups.len() >= 512 {
            return Err(DependencyError);
        }
        let mut alternatives = Vec::new();
        for relation in split_top(group, b'|')? {
            if alternatives.len() >= 128 {
                return Err(DependencyError);
            }
            alternatives.push(parse_relation(relation.trim())?);
        }
        groups.push(DependencyGroup { alternatives });
    }
    Ok(groups)
}

fn split_top(input: &str, separator: u8) -> Result<Vec<&str>, DependencyError> {
    let mut result = Vec::new();
    let mut open = None;
    let mut start = 0;
    for (i, byte) in input.bytes().enumerate() {
        match (open, byte) {
            (None, b'(') => open = Some(b')'),
            (None, b'[') => open = Some(b']'),
            (None, b'<') => open = Some(b'>'),
            (Some(close), c) if c == close => open = None,
            (None, b')' | b']' | b'>') => return Err(DependencyError),
            (None, c) if c == separator => {
                let part = input[start..i].trim();
                if part.is_empty() {
                    return Err(DependencyError);
                }
                result.push(part);
                start = i + 1;
            }
            _ => (),
        }
    }
    if open.is_some() {
        return Err(DependencyError);
    }
    let tail = input[start..].trim();
    if tail.is_empty() {
        return Err(DependencyError);
    }
    result.push(tail);
    Ok(result)
}

fn identifier(input: &str) -> bool {
    !input.is_empty()
        && input.len() <= 128
        && input
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && input
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
}
fn restrictions(input: &str) -> Result<Vec<String>, DependencyError> {
    let values: Vec<String> = input.split_ascii_whitespace().map(str::to_owned).collect();
    if values.is_empty()
        || values.len() > 128
        || values
            .iter()
            .any(|s| !identifier(s.strip_prefix('!').unwrap_or(s)))
    {
        return Err(DependencyError);
    }
    Ok(values)
}
fn take_delimited(input: &str, start: u8, end: u8) -> Result<(&str, &str), DependencyError> {
    let bytes = input.as_bytes();
    if bytes.first() != Some(&start) {
        return Err(DependencyError);
    }
    let end_pos = bytes
        .iter()
        .position(|b| *b == end)
        .ok_or(DependencyError)?;
    Ok((&input[1..end_pos], &input[end_pos + 1..]))
}
fn parse_relation(input: &str) -> Result<DependencyRelation, DependencyError> {
    let end = input
        .bytes()
        .position(|b| b.is_ascii_whitespace() || b":([<".contains(&b))
        .unwrap_or(input.len());
    let name = &input[..end];
    if !identifier(name) {
        return Err(DependencyError);
    }
    let mut rest = &input[end..];
    let mut qualifier = None;
    if let Some(value) = rest.strip_prefix(':') {
        let end = value
            .bytes()
            .position(|b| b.is_ascii_whitespace() || b"([<".contains(&b))
            .unwrap_or(value.len());
        let value = &value[..end];
        if !identifier(value) {
            return Err(DependencyError);
        }
        qualifier = Some(value.to_owned());
        rest = &rest[value.len() + 1..];
    }
    rest = rest.trim_start();
    let mut version = None;
    if rest.starts_with('(') {
        let (body, remaining) = take_delimited(rest, b'(', b')')?;
        let mut fields = body.split_ascii_whitespace();
        let operator = match fields.next() {
            Some("<<") => Comparison::Less,
            Some("<=") => Comparison::LessOrEqual,
            Some("=") => Comparison::Equal,
            Some(">=") => Comparison::GreaterOrEqual,
            Some(">>") => Comparison::Greater,
            _ => return Err(DependencyError),
        };
        let parsed = DebianVersion::parse(fields.next().ok_or(DependencyError)?)
            .map_err(|_| DependencyError)?;
        if fields.next().is_some() {
            return Err(DependencyError);
        }
        version = Some(VersionConstraint {
            operator,
            version: parsed,
        });
        rest = remaining.trim_start();
    }
    let mut architectures = Vec::new();
    if rest.starts_with('[') {
        let (body, remaining) = take_delimited(rest, b'[', b']')?;
        architectures = restrictions(body)?;
        rest = remaining.trim_start();
    }
    let mut profiles = Vec::new();
    while rest.starts_with('<') {
        if profiles.len() >= 128 {
            return Err(DependencyError);
        }
        let (body, remaining) = take_delimited(rest, b'<', b'>')?;
        profiles.push(restrictions(body)?);
        rest = remaining.trim_start();
    }
    if !rest.is_empty() {
        return Err(DependencyError);
    }
    Ok(DependencyRelation {
        name: name.to_owned(),
        qualifier,
        version,
        architectures,
        profiles,
    })
}
