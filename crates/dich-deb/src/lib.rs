#![forbid(unsafe_code)]
//! Bounded read-only Debian archive inspection. No extraction or installation.
use std::{
    error::Error,
    fmt,
    io::{Cursor, Read},
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_archive_bytes: usize,
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_total_file_bytes: u64,
    pub max_path_bytes: usize,
    pub max_depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 64 * 1024 * 1024,
            max_entries: 20_000,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_file_bytes: 128 * 1024 * 1024,
            max_path_bytes: 4096,
            max_depth: 64,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum DebError {
    Limit,
    Malformed,
    Unsupported,
}
impl fmt::Display for DebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Debian archive inspection failed: {self:?}")
    }
}
impl Error for DebError {}
#[derive(Debug, PartialEq, Eq)]
pub struct ArchiveReport {
    pub control_entries: usize,
    pub data_entries: usize,
    pub control_file_bytes: u64,
    pub data_file_bytes: u64,
}

/// Inspect an uncompressed, bounded .deb; no authenticity or installability is implied.
pub fn inspect_deb(bytes: &[u8], limits: Limits) -> Result<ArchiveReport, DebError> {
    if limits.max_archive_bytes == 0
        || limits.max_archive_bytes > 256 * 1024 * 1024
        || limits.max_entries == 0
        || limits.max_entries > 100_000
        || limits.max_file_bytes == 0
        || limits.max_file_bytes > 128 * 1024 * 1024
        || limits.max_total_file_bytes == 0
        || limits.max_total_file_bytes > 512 * 1024 * 1024
        || limits.max_path_bytes == 0
        || limits.max_path_bytes > 4096
        || limits.max_depth == 0
        || limits.max_depth > 128
        || bytes.len() > limits.max_archive_bytes
    {
        return Err(DebError::Limit);
    }
    preflight_ar(bytes)?;
    let mut archive = ar::Archive::new(Cursor::new(bytes));
    let mut members = Vec::new();
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry.map_err(|_| DebError::Malformed)?;
        let mut body = Vec::new();
        entry
            .read_to_end(&mut body)
            .map_err(|_| DebError::Malformed)?;
        members.push(body);
    }
    if members.len() != 3 || members[0] != b"2.0\n" {
        return Err(DebError::Unsupported);
    }
    let (control_entries, control_file_bytes) = inspect_tar(&members[1], limits, true)?;
    let (data_entries, data_file_bytes) = inspect_tar(&members[2], limits, false)?;
    if control_entries
        .checked_add(data_entries)
        .ok_or(DebError::Limit)?
        > limits.max_entries
        || control_file_bytes
            .checked_add(data_file_bytes)
            .ok_or(DebError::Limit)?
            > limits.max_total_file_bytes
    {
        return Err(DebError::Limit);
    }
    Ok(ArchiveReport {
        control_entries,
        data_entries,
        control_file_bytes,
        data_file_bytes,
    })
}

/// Block extended ar variants and oversized declared sizes before the library can allocate.
fn preflight_ar(bytes: &[u8]) -> Result<(), DebError> {
    if !bytes.starts_with(b"!<arch>\n") {
        return Err(DebError::Malformed);
    }
    let mut pos = 8usize;
    let names: [&[u8]; 3] = [b"debian-binary", b"control.tar", b"data.tar"];
    for expected in names {
        let header = bytes
            .get(pos..pos.checked_add(60).ok_or(DebError::Limit)?)
            .ok_or(DebError::Malformed)?;
        if &header[58..60] != b"`\n" {
            return Err(DebError::Malformed);
        }
        let name = &header[..16];
        let end = name.iter().position(|b| *b == b' ').unwrap_or(name.len());
        if name[..end] != *expected || name[end..].iter().any(|b| *b != b' ') {
            return Err(DebError::Unsupported);
        }
        let text = std::str::from_utf8(&header[48..58])
            .map_err(|_| DebError::Malformed)?
            .trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DebError::Malformed);
        }
        let size = text.parse::<usize>().map_err(|_| DebError::Limit)?;
        pos = pos
            .checked_add(60)
            .and_then(|p| p.checked_add(size))
            .ok_or(DebError::Limit)?;
        if pos > bytes.len() {
            return Err(DebError::Malformed);
        }
        if size % 2 != 0 {
            if bytes.get(pos) != Some(&b'\n') {
                return Err(DebError::Malformed);
            }
            pos = pos.checked_add(1).ok_or(DebError::Limit)?;
        }
    }
    if pos != bytes.len() {
        return Err(DebError::Unsupported);
    }
    Ok(())
}
fn inspect_tar(bytes: &[u8], limits: Limits, control: bool) -> Result<(usize, u64), DebError> {
    if bytes.len() < 1024 || bytes.len() % 512 != 0 {
        return Err(DebError::Malformed);
    }
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut count = 0usize;
    let mut total = 0u64;
    let mut control_files = 0usize;
    {
        let entries = archive
            .entries()
            .map_err(|_| DebError::Malformed)?
            .raw(true);
        for entry in entries {
            let mut entry = entry.map_err(|_| DebError::Malformed)?;
            count = count.checked_add(1).ok_or(DebError::Limit)?;
            let path = entry.path_bytes();
            if count > limits.max_entries
                || path.len() > limits.max_path_bytes
                || path.split(|b| *b == b'/').count() > limits.max_depth
            {
                return Err(DebError::Limit);
            }
            let kind = entry.header().entry_type();
            if !(kind.is_file() || kind.is_dir()) {
                return Err(DebError::Unsupported);
            }
            if control && (path.as_ref() == b"control" || path.as_ref() == b"./control") {
                if !kind.is_file() {
                    return Err(DebError::Malformed);
                }
                control_files += 1;
            }
            let size = entry.size();
            if size > limits.max_file_bytes {
                return Err(DebError::Limit);
            }
            total = total.checked_add(size).ok_or(DebError::Limit)?;
            if total > limits.max_total_file_bytes {
                return Err(DebError::Limit);
            }
            let copied =
                std::io::copy(&mut entry, &mut std::io::sink()).map_err(|_| DebError::Malformed)?;
            if copied != size {
                return Err(DebError::Malformed);
            }
        }
    }
    let pos = usize::try_from(archive.into_inner().position()).map_err(|_| DebError::Limit)?;
    if pos > bytes.len()
        || bytes.len().saturating_sub(pos) < 512
        || bytes[pos..].iter().any(|b| *b != 0)
    {
        return Err(DebError::Malformed);
    }
    if control && control_files != 1 {
        return Err(DebError::Malformed);
    }
    Ok((count, total))
}
