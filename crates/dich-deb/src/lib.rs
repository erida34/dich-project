#![forbid(unsafe_code)]
//! Bounded read-only Debian archive inspection. No extraction or installation.
#[cfg(target_os = "linux")]
mod staging;
#[cfg(target_os = "linux")]
pub use staging::{StageError, StagedArchive, StagedFile, stage_cached};

use serde::Serialize;

const MAX_PACKAGE_EVIDENCE_ITEMS: usize = 4096;
const MAX_PACKAGE_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PACKAGE_ELF_OBJECTS: usize = 256;
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
    Io,
    UnsafePath,
}
impl fmt::Display for DebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Debian archive inspection failed: {self:?}")
    }
}
impl Error for DebError {}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ScriptMetadata {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ArchiveReport {
    pub control_entries: usize,
    pub data_entries: usize,
    pub control_files: usize,
    pub data_files: usize,
    pub control_file_bytes: u64,
    pub data_file_bytes: u64,
    pub scripts: Vec<ScriptMetadata>,
    pub triggers_present: bool,
    /// File locations requiring explicit compatibility review; path names alone are not policy.
    pub path_indicators: PackagePathIndicators,
    pub elf_objects: Vec<ElfArchiveEvidence>,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ElfArchiveEvidence {
    pub path: String,
    pub report: dich_elf::ElfReport,
}
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct PackagePathIndicators {
    pub configuration_files: Vec<String>,
    pub service_units: Vec<String>,
    pub pkg_config_files: Vec<String>,
    pub cmake_files: Vec<String>,
    pub nss_locale_files: Vec<String>,
    pub shebangs: Vec<ShebangEvidence>,
    pub embedded_absolute_paths: Vec<EmbeddedPathEvidence>,
    pub host_integration_markers: Vec<ContentMarkerEvidence>,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ShebangEvidence {
    pub file: String,
    pub value: String,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct EmbeddedPathEvidence {
    pub file: String,
    pub line: usize,
    pub value: String,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ContentMarkerEvidence {
    pub file: String,
    pub line: usize,
    pub marker: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Supported,
    Unsupported,
    ReviewRequired,
}
impl CompatibilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::ReviewRequired => "review_required",
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CompatibilityEvidence {
    pub code: String,
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CompatibilityReport {
    pub schema_version: u32,
    pub status: CompatibilityStatus,
    pub evidence: Vec<CompatibilityEvidence>,
}

/// Produce an evidence-based compatibility status. Current policy never returns `supported`;
/// that result requires a later explicit package-class allowlist and validated fixtures.
pub fn assess_compatibility(archive: &ArchiveReport) -> CompatibilityReport {
    if let Some(path) = allowlisted_standalone_dso(archive) {
        return CompatibilityReport {
            schema_version: 1,
            status: CompatibilityStatus::Supported,
            evidence: vec![CompatibilityEvidence {
                code: "standalone_dso_allowlist_v1".into(),
                path: Some(path),
                detail: "self-contained shared object; caller must load its explicit store path; activation is not supported".into(),
            }],
        };
    }
    let mut evidence = Vec::new();
    let mut blocked = false;
    let mut add = |code: &str, path: Option<&str>, detail: String, unsupported: bool| {
        blocked |= unsupported;
        if evidence.len() < 512 {
            evidence.push(CompatibilityEvidence {
                code: code.to_owned(),
                path: path.map(str::to_owned),
                detail,
            });
        }
    };
    for script in &archive.scripts {
        add(
            "maintainer_script",
            Some(&format!("DEBIAN/{}", script.name)),
            "package contains an unexecuted maintainer script".into(),
            true,
        );
    }
    if archive.triggers_present {
        add(
            "maintainer_triggers",
            Some("DEBIAN/triggers"),
            "package declares maintainer triggers whose effects are not analyzed".into(),
            true,
        );
    }
    for path in &archive.path_indicators.service_units {
        add(
            "service_unit",
            Some(path),
            "system service integration is outside the supported store model".into(),
            true,
        );
    }
    for marker in &archive.path_indicators.host_integration_markers {
        let unsupported = matches!(
            marker.marker.as_str(),
            "systemctl"
                | "deb-systemd-invoke"
                | "invoke-rc.d"
                | "update-rc.d"
                | "ldconfig"
                | "locale-gen"
        );
        add(
            "host_integration_command",
            Some(&marker.file),
            format!("line {} references {}", marker.line, marker.marker),
            unsupported,
        );
    }
    for reference in &archive.path_indicators.embedded_absolute_paths {
        add(
            "embedded_absolute_path",
            Some(&reference.file),
            format!("line {} contains {}", reference.line, reference.value),
            false,
        );
    }
    for path in &archive.path_indicators.configuration_files {
        add(
            "configuration_file",
            Some(path),
            "package writes configuration under /etc".into(),
            false,
        );
    }
    for path in &archive.path_indicators.pkg_config_files {
        add(
            "pkg_config_metadata",
            Some(path),
            "pkg-config metadata may expose absolute build paths".into(),
            false,
        );
    }
    for path in &archive.path_indicators.cmake_files {
        add(
            "cmake_metadata",
            Some(path),
            "CMake metadata may expose absolute build paths".into(),
            false,
        );
    }
    for path in &archive.path_indicators.nss_locale_files {
        add(
            "nss_locale_integration",
            Some(path),
            "NSS or locale behavior requires runtime review".into(),
            false,
        );
    }
    for elf in &archive.elf_objects {
        if let Some(interpreter) = &elf.report.interpreter {
            add(
                "elf_interpreter",
                Some(&elf.path),
                format!("requires interpreter {interpreter}"),
                false,
            );
        }
        for library in &elf.report.needed {
            add(
                "elf_needed",
                Some(&elf.path),
                format!("needs dynamic library {library}"),
                false,
            );
        }
        for path in elf.report.rpath.iter().chain(&elf.report.runpath) {
            add(
                "elf_search_path",
                Some(&elf.path),
                format!("embeds loader search path {path}"),
                false,
            );
        }
        if !elf.report.required_symbol_versions.is_empty() {
            add(
                "elf_symbol_versions",
                Some(&elf.path),
                format!(
                    "requires {} symbol versions; libc compatibility is not established",
                    elf.report.required_symbol_versions.len()
                ),
                false,
            );
        }
        if !elf.report.dynamic_loading_symbols.is_empty() {
            add(
                "elf_dynamic_loading",
                Some(&elf.path),
                format!(
                    "imports dynamic loading functions: {}",
                    elf.report.dynamic_loading_symbols.join(", ")
                ),
                false,
            );
        }
        if elf.report.has_initializers {
            add(
                "elf_initializers",
                Some(&elf.path),
                "ELF contains initialization code that runs when loaded".into(),
                false,
            );
        }
        if elf.report.executable_stack_required || elf.report.writable_executable_segment {
            add(
                "elf_memory_permissions",
                Some(&elf.path),
                "ELF requests executable stack or writable executable memory".into(),
                true,
            );
        }
        if elf.report.has_ifunc_symbols {
            add(
                "elf_ifunc",
                Some(&elf.path),
                "ELF uses indirect functions resolved by executable code".into(),
                false,
            );
        }
        for path in &elf.report.absolute_path_literals {
            add(
                "elf_absolute_path_literal",
                Some(&elf.path),
                format!("ELF contains absolute path literal {path}"),
                false,
            );
        }
    }
    if evidence.is_empty() {
        evidence.push(CompatibilityEvidence {
            code: "no_allowlist_match".into(),
            path: None,
            detail: "absence of detected indicators is not compatibility evidence".into(),
        });
    } else if evidence.len() == 512 {
        evidence[511] = CompatibilityEvidence {
            code: "evidence_truncated".into(),
            path: None,
            detail: "additional findings were omitted from this bounded report".into(),
        };
    }
    CompatibilityReport {
        schema_version: 1,
        status: if blocked {
            CompatibilityStatus::Unsupported
        } else {
            CompatibilityStatus::ReviewRequired
        },
        evidence,
    }
}

fn allowlisted_standalone_dso(archive: &ArchiveReport) -> Option<String> {
    if archive.data_files != 1
        || !archive.scripts.is_empty()
        || archive.triggers_present
        || archive.elf_objects.len() != 1
        || !archive.path_indicators.configuration_files.is_empty()
        || !archive.path_indicators.service_units.is_empty()
        || !archive.path_indicators.pkg_config_files.is_empty()
        || !archive.path_indicators.cmake_files.is_empty()
        || !archive.path_indicators.nss_locale_files.is_empty()
        || !archive.path_indicators.shebangs.is_empty()
        || !archive.path_indicators.embedded_absolute_paths.is_empty()
        || !archive.path_indicators.host_integration_markers.is_empty()
    {
        return None;
    }
    let elf = &archive.elf_objects[0];
    let path = &elf.path;
    let report = &elf.report;
    let basename = path.rsplit('/').next()?;
    if !path.starts_with("usr/lib/")
        || !basename.ends_with(".so")
        || report.object_type != 3 // ELF ET_DYN
        || !report.is_shared_object
        || report.machine != host_elf_machine()?
        || report.interpreter.is_some()
        || report.soname.as_deref() != Some(basename)
        || !report.needed.is_empty()
        || !report.undefined_symbols.is_empty()
        || !report.required_symbol_versions.is_empty()
        || !report.dynamic_loading_symbols.is_empty()
        || !report.rpath.is_empty()
        || !report.runpath.is_empty()
        || report.has_initializers
        || report.executable_stack_required
        || report.writable_executable_segment
        || report.has_ifunc_symbols
        || !report.absolute_path_literals.is_empty()
    {
        return None;
    }
    Some(path.clone())
}

fn host_elf_machine() -> Option<u16> {
    if cfg!(target_arch = "x86_64") {
        Some(62)
    } else {
        None
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    fn empty_archive() -> ArchiveReport {
        ArchiveReport {
            control_entries: 0,
            data_entries: 0,
            control_files: 0,
            data_files: 0,
            control_file_bytes: 0,
            data_file_bytes: 0,
            scripts: Vec::new(),
            triggers_present: false,
            path_indicators: PackagePathIndicators::default(),
            elf_objects: Vec::new(),
        }
    }

    #[test]
    fn empty_evidence_requires_review_and_never_claims_support() {
        let report = assess_compatibility(&empty_archive());
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.status, CompatibilityStatus::ReviewRequired);
        assert_eq!(report.evidence[0].code, "no_allowlist_match");
    }

    #[test]
    fn evidence_output_is_bounded_and_keeps_conservative_status() {
        let mut archive = empty_archive();
        archive.path_indicators.configuration_files =
            (0..700).map(|n| format!("etc/example/{n}.conf")).collect();
        let report = assess_compatibility(&archive);
        assert_eq!(report.status, CompatibilityStatus::ReviewRequired);
        assert_eq!(report.evidence.len(), 512);
        assert_eq!(report.evidence[511].code, "evidence_truncated");
    }
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
    let control_report = inspect_tar(&control, limits, true)?;
    let data_report = inspect_tar(&data, limits, false)?;
    if control_report
        .entries
        .checked_add(data_report.entries)
        .ok_or(DebError::Limit)?
        > limits.max_entries
        || control_report
            .files
            .checked_add(data_report.files)
            .ok_or(DebError::Limit)?
            > limits.max_files
        || control_report
            .total_bytes
            .checked_add(data_report.total_bytes)
            .ok_or(DebError::Limit)?
            > limits.max_total_file_bytes
    {
        return Err(DebError::Limit);
    }
    let mut path_indicators = data_report.path_indicators;
    path_indicators
        .shebangs
        .extend(control_report.path_indicators.shebangs);
    path_indicators
        .embedded_absolute_paths
        .extend(control_report.path_indicators.embedded_absolute_paths);
    path_indicators
        .host_integration_markers
        .extend(control_report.path_indicators.host_integration_markers);
    Ok(ArchiveReport {
        control_entries: control_report.entries,
        data_entries: data_report.entries,
        control_files: control_report.files,
        data_files: data_report.files,
        control_file_bytes: control_report.total_bytes,
        data_file_bytes: data_report.total_bytes,
        scripts: control_report.scripts,
        triggers_present: control_report.triggers_present,
        path_indicators,
        elf_objects: data_report.elf_objects,
    })
}

/// Inspect a bounded regular local file without following symlinks. This does not authenticate it.
#[cfg(target_os = "linux")]
pub fn inspect_path(path: &std::path::Path, limits: Limits) -> Result<ArchiveReport, DebError> {
    use rustix::fs::{self, CWD, FileType, Mode, OFlags, ResolveFlags};
    if limits.max_archive_bytes == 0 || limits.max_archive_bytes > 256 * 1024 * 1024 {
        return Err(DebError::Limit);
    }
    let fd = fs::openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| DebError::UnsafePath)?;
    let stat = fs::fstat(&fd).map_err(|_| DebError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_size < 0 {
        return Err(DebError::UnsafePath);
    }
    if stat.st_size as u64 > limits.max_archive_bytes as u64 {
        return Err(DebError::Limit);
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(limits.max_archive_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DebError::Io)?;
    if bytes.len() > limits.max_archive_bytes || bytes.len() as u64 != stat.st_size as u64 {
        return Err(DebError::Limit);
    }
    inspect_deb(&bytes, limits)
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
struct TarReport {
    entries: usize,
    files: usize,
    total_bytes: u64,
    scripts: Vec<ScriptMetadata>,
    triggers_present: bool,
    path_indicators: PackagePathIndicators,
    elf_objects: Vec<ElfArchiveEvidence>,
}

fn inspect_tar(bytes: &[u8], limits: Limits, control: bool) -> Result<TarReport, DebError> {
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
    let mut path_indicators = PackagePathIndicators::default();
    let mut elf_objects = Vec::new();
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
            if !control && kind.is_file() {
                record_path_indicators(&mut path_indicators, &normalized)?;
            }
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
            paths.insert(normalized.clone(), kind.is_dir());
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
            let mut content =
                Vec::with_capacity(usize::try_from(size).map_err(|_| DebError::Limit)?);
            entry
                .by_ref()
                .take(size.checked_add(1).ok_or(DebError::Limit)?)
                .read_to_end(&mut content)
                .map_err(|_| DebError::Malformed)?;
            if content.len() as u64 != size {
                return Err(DebError::Malformed);
            }
            let scan_path = if control {
                format!("DEBIAN/{}", String::from_utf8_lossy(&normalized))
            } else {
                String::from_utf8(normalized.clone()).map_err(|_| DebError::Unsupported)?
            };
            scan_content_indicators(&mut path_indicators, &scan_path, &content)?;
            ensure_indicator_limits(&path_indicators)?;
            if !control {
                if let Some(report) =
                    dich_elf::inspect_elf(&content).map_err(|_| DebError::Unsupported)?
                {
                    if elf_objects.len() >= MAX_PACKAGE_ELF_OBJECTS
                        || elf_report_bytes(&report)
                            .checked_add(
                                elf_objects
                                    .iter()
                                    .map(|item: &ElfArchiveEvidence| elf_report_bytes(&item.report))
                                    .sum::<usize>(),
                            )
                            .ok_or(DebError::Limit)?
                            > MAX_PACKAGE_EVIDENCE_BYTES
                    {
                        return Err(DebError::Limit);
                    }
                    elf_objects.push(ElfArchiveEvidence {
                        path: scan_path.clone(),
                        report,
                    });
                }
            }
            if let Some(name) = metadata_name {
                use sha2::{Digest, Sha256};
                let hash: String = Sha256::digest(&content)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                scripts.push(ScriptMetadata {
                    name: name.into(),
                    size,
                    sha256: hash,
                });
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
    Ok(TarReport {
        entries: count,
        files,
        total_bytes: total,
        scripts,
        triggers_present,
        path_indicators,
        elf_objects,
    })
}

fn record_path_indicators(
    indicators: &mut PackagePathIndicators,
    path: &[u8],
) -> Result<(), DebError> {
    let path = std::str::from_utf8(path).map_err(|_| DebError::Unsupported)?;
    let lower = path.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);
    let record = |collection: &mut Vec<String>| -> Result<(), DebError> {
        if collection.len() >= 2048 || path.len() > 4096 {
            return Err(DebError::Limit);
        }
        collection.push(path.to_owned());
        Ok(())
    };
    if lower.starts_with("etc/") {
        record(&mut indicators.configuration_files)?;
    }
    if [
        "lib/systemd/system/",
        "usr/lib/systemd/system/",
        "usr/lib/systemd/user/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        && [
            ".service", ".socket", ".target", ".timer", ".path", ".mount", ".slice",
        ]
        .iter()
        .any(|suffix| file_name.ends_with(suffix))
    {
        record(&mut indicators.service_units)?;
    }
    if file_name.ends_with(".pc") {
        record(&mut indicators.pkg_config_files)?;
    }
    if file_name.ends_with(".cmake") || lower.contains("/cmake/") {
        record(&mut indicators.cmake_files)?;
    }
    if lower == "etc/nsswitch.conf"
        || lower.starts_with("usr/share/locale/")
        || lower.starts_with("usr/lib/locale/")
        || file_name.starts_with("libnss_")
    {
        record(&mut indicators.nss_locale_files)?;
    }
    Ok(())
}

fn scan_content_indicators(
    indicators: &mut PackagePathIndicators,
    file: &str,
    bytes: &[u8],
) -> Result<(), DebError> {
    if bytes.starts_with(b"#!") {
        let end = bytes
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(bytes.len());
        let value = std::str::from_utf8(&bytes[..end]).map_err(|_| DebError::Unsupported)?;
        if value.len() > 4096 || indicators.shebangs.len() >= 4096 {
            return Err(DebError::Limit);
        }
        indicators.shebangs.push(ShebangEvidence {
            file: file.to_owned(),
            value: value.to_owned(),
        });
    }
    if bytes.contains(&0) {
        return Ok(());
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(());
    };
    for (line_index, line) in text.lines().enumerate() {
        for token in line.split(|c: char| c.is_ascii_whitespace() || "=\"'(),;".contains(c)) {
            if token.starts_with('/') {
                if indicators.embedded_absolute_paths.len() >= 4096 || token.len() > 4096 {
                    return Err(DebError::Limit);
                }
                indicators
                    .embedded_absolute_paths
                    .push(EmbeddedPathEvidence {
                        file: file.to_owned(),
                        line: line_index + 1,
                        value: token.to_owned(),
                    });
            }
        }
        for marker in [
            "systemctl",
            "deb-systemd-invoke",
            "invoke-rc.d",
            "update-rc.d",
            "ldconfig",
            "locale-gen",
            "nsswitch.conf",
        ] {
            if line
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
                .any(|word| word == marker)
            {
                if indicators.host_integration_markers.len() >= 4096 {
                    return Err(DebError::Limit);
                }
                indicators
                    .host_integration_markers
                    .push(ContentMarkerEvidence {
                        file: file.to_owned(),
                        line: line_index + 1,
                        marker: marker.to_owned(),
                    });
            }
        }
    }
    Ok(())
}

fn ensure_indicator_limits(indicators: &PackagePathIndicators) -> Result<(), DebError> {
    let paths = indicators
        .configuration_files
        .iter()
        .chain(&indicators.service_units)
        .chain(&indicators.pkg_config_files)
        .chain(&indicators.cmake_files)
        .chain(&indicators.nss_locale_files);
    let path_items = paths.clone().count();
    let path_bytes = paths.map(String::len).sum::<usize>();
    let content_items = indicators.shebangs.len()
        + indicators.embedded_absolute_paths.len()
        + indicators.host_integration_markers.len();
    let content_bytes = indicators
        .shebangs
        .iter()
        .map(|item| item.file.len() + item.value.len())
        .chain(
            indicators
                .embedded_absolute_paths
                .iter()
                .map(|item| item.file.len() + item.value.len()),
        )
        .chain(
            indicators
                .host_integration_markers
                .iter()
                .map(|item| item.file.len() + item.marker.len()),
        )
        .sum::<usize>();
    if path_items + content_items > MAX_PACKAGE_EVIDENCE_ITEMS
        || path_bytes + content_bytes > MAX_PACKAGE_EVIDENCE_BYTES
    {
        return Err(DebError::Limit);
    }
    Ok(())
}

fn elf_report_bytes(report: &dich_elf::ElfReport) -> usize {
    report.interpreter.as_ref().map_or(0, String::len)
        + report.soname.as_ref().map_or(0, String::len)
        + report
            .needed
            .iter()
            .chain(&report.rpath)
            .chain(&report.runpath)
            .chain(&report.required_symbol_versions)
            .chain(&report.dynamic_loading_symbols)
            .chain(&report.undefined_symbols)
            .chain(&report.absolute_path_literals)
            .map(String::len)
            .sum::<usize>()
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
