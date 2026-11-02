//! Debian package version validation and ordering.
use std::{cmp::Ordering, error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionError;
impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Debian version")
    }
}
impl Error for VersionError {}

/// A parsed Debian version. Equality follows Debian ordering, not textual identity.
#[derive(Debug, Clone)]
pub struct DebianVersion {
    raw: String,
    epoch_end: usize,
    upstream_start: usize,
    upstream_end: usize,
    revision_start: Option<usize>,
}
impl DebianVersion {
    pub fn parse(raw: &str) -> Result<Self, VersionError> {
        if raw.is_empty() || raw.len() > 4096 || !raw.is_ascii() {
            return Err(VersionError);
        }
        let (epoch_end, upstream_start) = match raw.find(':') {
            Some(pos) if pos > 0 && raw[..pos].bytes().all(|b| b.is_ascii_digit()) => {
                (pos, pos + 1)
            }
            Some(_) => return Err(VersionError),
            None => (0, 0),
        };
        let rest = &raw[upstream_start..];
        let (upstream, revision, upstream_end, revision_start) = match rest.rfind('-') {
            Some(pos) => (
                &rest[..pos],
                Some(&rest[pos + 1..]),
                upstream_start + pos,
                Some(upstream_start + pos + 1),
            ),
            None => (rest, None, raw.len(), None),
        };
        if !upstream.as_bytes().first().is_some_and(u8::is_ascii_digit)
            || !upstream
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+:~-".contains(&b))
            || revision.is_some_and(|r| {
                r.is_empty()
                    || !r
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".+~".contains(&b))
            })
        {
            return Err(VersionError);
        }
        Ok(Self {
            raw: raw.to_owned(),
            epoch_end,
            upstream_start,
            upstream_end,
            revision_start,
        })
    }
    pub fn as_str(&self) -> &str {
        &self.raw
    }
    fn epoch(&self) -> &str {
        if self.epoch_end == 0 {
            "0"
        } else {
            &self.raw[..self.epoch_end]
        }
    }
    fn upstream(&self) -> &str {
        &self.raw[self.upstream_start..self.upstream_end]
    }
    fn revision(&self) -> &str {
        self.revision_start.map_or("0", |pos| &self.raw[pos..])
    }
}

fn numeric(a: &[u8], b: &[u8]) -> Ordering {
    let a = a
        .iter()
        .position(|c| *c != b'0')
        .map_or(&a[a.len()..], |i| &a[i..]);
    let b = b
        .iter()
        .position(|c| *c != b'0')
        .map_or(&b[b.len()..], |i| &b[i..]);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}
fn non_digit_order(c: Option<u8>) -> i16 {
    match c {
        Some(b'~') => -1,
        None | Some(b'0'..=b'9') => 0,
        Some(c) if c.is_ascii_alphabetic() => i16::from(c),
        Some(c) => i16::from(c) + 256,
    }
}
fn version_part(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while a.get(i).is_some_and(|c| !c.is_ascii_digit())
            || b.get(j).is_some_and(|c| !c.is_ascii_digit())
        {
            let ordering =
                non_digit_order(a.get(i).copied()).cmp(&non_digit_order(b.get(j).copied()));
            if ordering != Ordering::Equal {
                return ordering;
            }
            if a.get(i).is_some_and(|c| !c.is_ascii_digit()) {
                i += 1;
            }
            if b.get(j).is_some_and(|c| !c.is_ascii_digit()) {
                j += 1;
            }
        }
        let (start_i, start_j) = (i, j);
        while a.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        while b.get(j).is_some_and(u8::is_ascii_digit) {
            j += 1;
        }
        let ordering = numeric(&a[start_i..i], &b[start_j..j]);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}
impl Ord for DebianVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        numeric(self.epoch().as_bytes(), other.epoch().as_bytes())
            .then_with(|| version_part(self.upstream(), other.upstream()))
            .then_with(|| version_part(self.revision(), other.revision()))
    }
}
impl PartialOrd for DebianVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for DebianVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for DebianVersion {}
