//! Bounded Debian control stanza parsing; parsing does not authenticate data.
use std::{collections::BTreeMap, error::Error, fmt};

const MAX_INPUT: usize = 256 * 1024 * 1024;
const MAX_FIELD: usize = 1024 * 1024;
const MAX_FIELDS: usize = 1024;
const MAX_STANZAS: usize = 1_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum ControlError {
    InputTooLarge,
    Malformed,
    LimitExceeded,
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Debian control input: {self:?}")
    }
}
impl Error for ControlError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlStanza {
    fields: BTreeMap<String, String>,
}
impl ControlStanza {
    /// Field lookup is ASCII case-insensitive; continuation lines are joined with newlines.
    pub fn get(&self, field: &str) -> Option<&str> {
        self.fields
            .get(&field.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// Parse control paragraphs from bounded UTF-8 input; no semantic or authenticity checks.
pub fn parse_control_stanzas(input: &[u8]) -> Result<Vec<ControlStanza>, ControlError> {
    if input.len() > MAX_INPUT {
        return Err(ControlError::InputTooLarge);
    }
    let input = std::str::from_utf8(input).map_err(|_| ControlError::Malformed)?;
    if input
        .bytes()
        .any(|b| b == 0 || (b.is_ascii_control() && !matches!(b, b'\n' | b'\r' | b'\t')))
    {
        return Err(ControlError::Malformed);
    }
    let mut output = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut previous: Option<String> = None;
    for line in input.lines().chain(std::iter::once("")) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.contains('\r') {
            return Err(ControlError::Malformed);
        }
        if line.is_empty() {
            if !fields.is_empty() {
                if output.len() >= MAX_STANZAS {
                    return Err(ControlError::LimitExceeded);
                }
                output.push(ControlStanza {
                    fields: std::mem::take(&mut fields),
                });
            }
            previous = None;
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let key = previous.as_ref().ok_or(ControlError::Malformed)?;
            let value = fields.get_mut(key).ok_or(ControlError::Malformed)?;
            let part = &line[1..];
            if value.len().saturating_add(part.len()).saturating_add(1) > MAX_FIELD {
                return Err(ControlError::LimitExceeded);
            }
            value.push('\n');
            value.push_str(part);
        } else {
            let (name, value) = line.split_once(':').ok_or(ControlError::Malformed)?;
            if name.is_empty()
                || name.len() > 128
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(ControlError::Malformed);
            }
            let value = value.trim_start_matches([' ', '\t']);
            if value.len() > MAX_FIELD || fields.len() >= MAX_FIELDS {
                return Err(ControlError::LimitExceeded);
            }
            let name = name.to_ascii_lowercase();
            if fields.insert(name.clone(), value.to_owned()).is_some() {
                return Err(ControlError::Malformed);
            }
            previous = Some(name);
        }
    }
    Ok(output)
}
