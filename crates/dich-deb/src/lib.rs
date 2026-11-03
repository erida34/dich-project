#![forbid(unsafe_code)]
//! Bounded read-only Debian archive inspection. No extraction or installation.
#[cfg(target_os = "linux")]
mod staging;
#[cfg(target_os = "linux")]
pub use staging::{StageError, StagedArchive, StagedFile, stage_cached};

use std::{
    error::Error,
    fmt,
    io::{Cursor, Read},
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_archive_bytes: usize,
    pub max_expanded_tar_bytes: usize,
    pub max_entries: usize,
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_file_bytes: u64,
    pub max_path_bytes: usize,
    pub max_depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 64 * 1024 * 1024,
            max_expanded_tar_bytes: 128 * 1024 * 1024,
            max_entries: 20_000,
            max_files: 15_000,
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
    HelperUnavailable,
    Decompression,
}
impl fmt::Display for DebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Debian archive inspection failed: {self:?}")
    }
}
impl Error for DebError {}
#[derive(Debug, PartialEq, Eq)]
pub struct ScriptMetadata {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Debug, PartialEq, Eq)]
pub struct ArchiveReport {
    pub control_entries: usize,
    pub data_entries: usize,
    pub control_files: usize,
    pub data_files: usize,
    pub control_file_bytes: u64,
    pub data_file_bytes: u64,
    pub scripts: Vec<ScriptMetadata>,
    pub triggers_present: bool,
}

/// Inspect a bounded .deb; no authenticity or installability is implied.
pub fn inspect_deb(bytes: &[u8], limits: Limits) -> Result<ArchiveReport, DebError> {
    if limits.max_archive_bytes == 0
        || limits.max_archive_bytes > 256 * 1024 * 1024
        || limits.max_expanded_tar_bytes == 0
        || limits.max_expanded_tar_bytes > 256 * 1024 * 1024
        || limits.max_entries == 0
        || limits.max_entries > 100_000
        || limits.max_files == 0
        || limits.max_files > 100_000
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
    let formats = preflight_ar(bytes)?;
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
    let control = decompress(formats[0], &members[1], limits.max_expanded_tar_bytes)?;
    let data = decompress(formats[1], &members[2], limits.max_expanded_tar_bytes)?;
    let (control_entries, control_files, control_file_bytes, scripts, triggers_present) =
        inspect_tar(&control, limits, true)?;
    let (data_entries, data_files, data_file_bytes, _, _) = inspect_tar(&data, limits, false)?;
    if control_entries
        .checked_add(data_entries)
        .ok_or(DebError::Limit)?
        > limits.max_entries
        || control_files
            .checked_add(data_files)
            .ok_or(DebError::Limit)?
            > limits.max_files
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
        control_files,
        data_files,
        control_file_bytes,
        data_file_bytes,
        scripts,
        triggers_present,
    })
}

/// Block extended ar variants and oversized declared sizes before the library can allocate.
#[derive(Debug, Clone, Copy)]
enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
}
fn preflight_ar(bytes: &[u8]) -> Result<[Compression; 2], DebError> {
    if !bytes.starts_with(b"!<arch>\n") {
        return Err(DebError::Malformed);
    }
    let mut pos = 8usize;
    let mut formats = [Compression::None; 2];
    for index in 0..3 {
        let header = bytes
            .get(pos..pos.checked_add(60).ok_or(DebError::Limit)?)
            .ok_or(DebError::Malformed)?;
        if &header[58..60] != b"`\n" {
            return Err(DebError::Malformed);
        }
        let name = &header[..16];
        let end = name.iter().position(|b| *b == b' ').unwrap_or(name.len());
        if name[end..].iter().any(|b| *b != b' ') {
            return Err(DebError::Unsupported);
        }
        let member = &name[..end];
        if index == 0 {
            if member != b"debian-binary" {
                return Err(DebError::Unsupported);
            }
        } else {
            let prefix: &[u8] = if index == 1 {
                b"control.tar"
            } else {
                b"data.tar"
            };
            let suffix = member.strip_prefix(prefix).ok_or(DebError::Unsupported)?;
            formats[index - 1] = match suffix {
                b"" => Compression::None,
                b".gz" => Compression::Gzip,
                b".xz" => Compression::Xz,
                b".zst" => Compression::Zstd,
                _ => return Err(DebError::Unsupported),
            };
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
    Ok(formats)
}
fn inspect_tar(
    bytes: &[u8],
    limits: Limits,
    control: bool,
) -> Result<(usize, usize, u64, Vec<ScriptMetadata>, bool), DebError> {
    if bytes.len() < 1024 || bytes.len() % 512 != 0 {
        return Err(DebError::Malformed);
    }
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut count = 0usize;
    let mut total = 0u64;
    let mut files = 0usize;
    let mut control_files = 0usize;
    let mut scripts = Vec::new();
    let mut triggers_present = false;
    let mut paths: std::collections::BTreeMap<Vec<u8>, bool> = std::collections::BTreeMap::new();
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
            let mode = entry.header().mode().map_err(|_| DebError::Malformed)?;
            if mode & !0o777 != 0 {
                return Err(DebError::Unsupported);
            }
            let normalized = normalize_path(&path, kind.is_dir())?;
            if paths.contains_key(&normalized) {
                return Err(DebError::Malformed);
            }
            for (index, byte) in normalized.iter().enumerate() {
                if *byte == b'/' && paths.get(&normalized[..index]) == Some(&false) {
                    return Err(DebError::Malformed);
                }
            }
            if kind.is_file() {
                let mut prefix = normalized.clone();
                prefix.push(b'/');
                if paths
                    .range(prefix.clone()..)
                    .next()
                    .is_some_and(|(key, _)| key.starts_with(&prefix))
                {
                    return Err(DebError::Malformed);
                }
            }
            let metadata_name = if control && kind.is_file() {
                match normalized.as_slice() {
                    b"preinst" => Some("preinst"),
                    b"postinst" => Some("postinst"),
                    b"prerm" => Some("prerm"),
                    b"postrm" => Some("postrm"),
                    b"config" => Some("config"),
                    _ => None,
                }
            } else {
                None
            };
            if control && normalized == b"triggers" {
                if !kind.is_file() {
                    return Err(DebError::Malformed);
                }
                triggers_present = true;
            }
            paths.insert(normalized, kind.is_dir());
            if kind.is_file() {
                files = files.checked_add(1).ok_or(DebError::Limit)?;
                if files > limits.max_files {
                    return Err(DebError::Limit);
                }
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
            let copied = if let Some(name) = metadata_name {
                use sha2::{Digest, Sha256};
                let mut digest = Sha256::new();
                let mut buf = [0u8; 8192];
                let mut count = 0u64;
                loop {
                    let read = entry.read(&mut buf).map_err(|_| DebError::Malformed)?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buf[..read]);
                    count = count.checked_add(read as u64).ok_or(DebError::Limit)?;
                }
                let hash: String = digest
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                scripts.push(ScriptMetadata {
                    name: name.into(),
                    size: count,
                    sha256: hash,
                });
                count
            } else {
                std::io::copy(&mut entry, &mut std::io::sink()).map_err(|_| DebError::Malformed)?
            };
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
    Ok((count, files, total, scripts, triggers_present))
}

fn normalize_path(path: &[u8], directory: bool) -> Result<Vec<u8>, DebError> {
    if path.is_empty()
        || path.first() == Some(&b'/')
        || path.iter().any(|b| *b == b'\\' || b.is_ascii_control())
        || std::str::from_utf8(path).is_err()
    {
        return Err(DebError::Unsupported);
    }
    let mut trimmed = path;
    if trimmed.starts_with(b"./") {
        trimmed = &trimmed[2..];
    }
    if trimmed.last() == Some(&b'/') {
        if !directory {
            return Err(DebError::Malformed);
        }
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    if trimmed == b"." || trimmed.is_empty() {
        return if directory {
            Ok(Vec::new())
        } else {
            Err(DebError::Unsupported)
        };
    }
    if trimmed
        .split(|b| *b == b'/')
        .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(DebError::Unsupported);
    }
    Ok(trimmed.to_vec())
}

#[cfg(not(target_os = "linux"))]
fn decompress(format: Compression, bytes: &[u8], limit: usize) -> Result<Vec<u8>, DebError> {
    if !matches!(format, Compression::None) {
        return Err(DebError::HelperUnavailable);
    }
    if bytes.len() > limit {
        return Err(DebError::Limit);
    }
    Ok(bytes.to_vec())
}
#[cfg(target_os = "linux")]
fn decompress(format: Compression, bytes: &[u8], limit: usize) -> Result<Vec<u8>, DebError> {
    use std::{
        io::{Seek, SeekFrom, Write},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    if matches!(format, Compression::None) {
        if bytes.len() > limit {
            return Err(DebError::Limit);
        }
        return Ok(bytes.to_vec());
    }
    let mut input = tempfile::tempfile().map_err(|_| DebError::HelperUnavailable)?;
    let mut output = tempfile::tempfile().map_err(|_| DebError::HelperUnavailable)?;
    input
        .write_all(bytes)
        .map_err(|_| DebError::HelperUnavailable)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| DebError::HelperUnavailable)?;
    let mut command = Command::new("/usr/bin/prlimit");
    command.arg(format!("--fsize={limit}:{limit}"));
    command.args([
        "--as=268435456:268435456",
        "--cpu=15:15",
        "--nofile=64:64",
        "--core=0:0",
        "--",
    ]);
    match format {
        Compression::Gzip => {
            command.args(["/usr/bin/gzip", "--decompress", "--stdout"]);
        }
        Compression::Xz => {
            command.args([
                "/usr/bin/xz",
                "--format=xz",
                "--memlimit-decompress=67108864",
                "--decompress",
                "--stdout",
            ]);
        }
        Compression::Zstd => {
            command.args([
                "/usr/bin/zstd",
                "--decompress",
                "--stdout",
                "--quiet",
                "-M64MB",
            ]);
        }
        Compression::None => return Err(DebError::Unsupported),
    }
    let stdout = output
        .try_clone()
        .map_err(|_| DebError::HelperUnavailable)?;
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| DebError::HelperUnavailable)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DebError::Decompression);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(DebError::Decompression);
            }
        }
    };
    if !status.success() {
        return Err(DebError::Decompression);
    }
    output
        .seek(SeekFrom::Start(0))
        .map_err(|_| DebError::Decompression)?;
    let mut expanded = Vec::new();
    output
        .take((limit + 1) as u64)
        .read_to_end(&mut expanded)
        .map_err(|_| DebError::Decompression)?;
    if expanded.len() > limit {
        return Err(DebError::Limit);
    }
    Ok(expanded)
}

#[cfg(all(test, target_os = "linux"))]
mod staging_tests {
    use super::*;
    use std::io::Cursor;
    fn sample(path: &str, data: &[u8]) -> Vec<u8> {
        let mut control = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut control);
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "control", &b"x"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut payload = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut payload);
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, data).unwrap();
            builder.finish().unwrap();
        }
        let mut output = Vec::new();
        {
            let mut builder = ar::Builder::new(&mut output);
            for (name, content) in [
                ("debian-binary", b"2.0\n".as_slice()),
                ("control.tar", control.as_slice()),
                ("data.tar", payload.as_slice()),
            ] {
                let header = ar::Header::new(name.as_bytes().to_vec(), content.len() as u64);
                builder.append(&header, Cursor::new(content)).unwrap();
            }
        }
        output
    }
    #[test]
    fn stages_file_in_private_directory_without_preserving_archive_modes() {
        let bytes = sample("usr/share/example", b"data");
        let stage = crate::staging::stage_untrusted_for_test(&bytes, Limits::default()).unwrap();
        use std::io::Read;
        let mut file = stage.open_file("usr/share/example").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"data");
        assert_eq!(stage.files().len(), 1);
        assert_eq!(stage.files()[0].path, "usr/share/example");
        assert_eq!(stage.files()[0].size, 4);
        assert_eq!(
            stage.files()[0].sha256,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );
        assert_eq!(
            stage.directories(),
            &["usr".to_string(), "usr/share".to_string()]
        );
        assert!(stage.open_file("../etc/passwd").is_err());
        assert!(stage.open_file("/etc/passwd").is_err());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
    #[test]
    fn staging_refuses_an_injected_symlink_and_leaves_target_untouched() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        let bytes = sample("usr/share/example", b"attack");
        let result = crate::staging::stage_with_test_hook(&bytes, Limits::default(), |stage| {
            symlink(outside.path(), stage.join("usr")).unwrap();
        });
        assert!(result.is_err());
        assert!(!outside.path().join("share").exists());
    }
    #[test]
    fn staging_refuses_root_directory_replacement() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        let bytes = sample("usr/share/example", b"attack");
        let mut replaced_path = None;
        let result = crate::staging::stage_with_test_hook(&bytes, Limits::default(), |stage| {
            replaced_path = Some(stage.to_path_buf());
            std::fs::rename(stage, outside.path().join("moved")).unwrap();
            symlink(outside.path(), stage).unwrap();
        });
        assert!(result.is_err());
        assert!(!outside.path().join("usr").exists());
        assert!(!outside.path().join("moved/usr").exists());
        match std::fs::remove_file(replaced_path.unwrap()) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => panic!("could not remove test symlink: {error}"),
        }
    }
    #[test]
    fn staging_refuses_existing_file_without_overwrite() {
        let bytes = sample("usr/share/example", b"attack");
        let result = crate::staging::stage_with_test_hook(&bytes, Limits::default(), |stage| {
            std::fs::create_dir_all(stage.join("usr/share")).unwrap();
            std::fs::write(stage.join("usr/share/example"), b"existing").unwrap();
        });
        assert!(result.is_err());
    }
    #[test]
    fn concurrent_symlink_swaps_never_write_into_external_target() {
        use std::{
            os::unix::fs::symlink,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
        };
        for _ in 0..10 {
            let outside = tempfile::tempdir().unwrap();
            let bytes = sample("usr/share/example", b"attack");
            let running = Arc::new(AtomicBool::new(true));
            let mut thread = None;
            let _result =
                crate::staging::stage_with_test_hook(&bytes, Limits::default(), |stage| {
                    let path = stage.join("usr");
                    let target = outside.path().to_owned();
                    let running = running.clone();
                    thread = Some(std::thread::spawn(move || {
                        while running.load(Ordering::Relaxed) {
                            let _ = std::fs::remove_file(&path);
                            let _ = std::fs::create_dir(&path);
                            let _ = std::fs::remove_dir(&path);
                            let _ = symlink(&target, &path);
                        }
                    }));
                });
            running.store(false, Ordering::Relaxed);
            thread.unwrap().join().unwrap();
            assert!(!outside.path().join("share/example").exists());
        }
    }
    #[test]
    fn staged_hardlink_collision_does_not_change_external_file() {
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("protected");
        std::fs::write(&target, b"original").unwrap();
        let bytes = sample("usr/share/example", b"attack");
        let result = crate::staging::stage_with_test_hook(&bytes, Limits::default(), |stage| {
            std::fs::create_dir_all(stage.join("usr/share")).unwrap();
            std::fs::hard_link(&target, stage.join("usr/share/example")).unwrap();
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"original");
    }
    #[test]
    fn staging_never_executes_control_scripts() {
        let outside = tempfile::tempdir().unwrap();
        let marker = outside.path().join("executed");
        let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
        let mut control = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut control);
            for (name, content) in [
                ("control", b"metadata".as_slice()),
                ("postinst", script.as_bytes()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                builder.append_data(&mut header, name, content).unwrap();
            }
            builder.finish().unwrap();
        }
        let existing = sample("usr/share/example", b"data");
        let mut input = ar::Archive::new(Cursor::new(existing));
        let mut payload = Vec::new();
        for index in 0..3 {
            let mut entry = input.next_entry().unwrap().unwrap();
            if index == 2 {
                std::io::Read::read_to_end(&mut entry, &mut payload).unwrap();
            }
        }
        let mut archive = Vec::new();
        {
            let mut builder = ar::Builder::new(&mut archive);
            for (name, content) in [
                ("debian-binary", b"2.0\n".as_slice()),
                ("control.tar", control.as_slice()),
                ("data.tar", payload.as_slice()),
            ] {
                let header = ar::Header::new(name.as_bytes().to_vec(), content.len() as u64);
                builder.append(&header, Cursor::new(content)).unwrap();
            }
        }
        let stage = crate::staging::stage_untrusted_for_test(&archive, Limits::default()).unwrap();
        assert!(!marker.exists());
        assert_eq!(stage.report().scripts[0].name, "postinst");
        assert!(stage.open_file("postinst").is_err());
        assert!(stage.open_file("usr/share/example").is_ok());
    }
}
