//! Verify Packages index bytes against signed Release metadata before decompression.
use crate::VerifiedRelease;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const MAX_COMPRESSED: usize = 256 * 1024 * 1024;
const MAX_EXPANDED: usize = 1024 * 1024 * 1024;

/// Per-index limits; the ceilings bound memory and temporary disk use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexLimits {
    compressed: usize,
    expanded: usize,
}
impl IndexLimits {
    pub fn new(compressed: usize, expanded: usize) -> Result<Self, IndexError> {
        if compressed == 0
            || compressed > MAX_COMPRESSED
            || expanded == 0
            || expanded > MAX_EXPANDED
        {
            return Err(IndexError::TooLarge);
        }
        Ok(Self {
            compressed,
            expanded,
        })
    }
}
impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            compressed: 64 * 1024 * 1024,
            expanded: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFormat {
    Gzip,
    Xz,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IndexError {
    InvalidMetadata,
    PolicyMismatch,
    Integrity,
    TooLarge,
    Decompression,
    HelperUnavailable,
}
impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index verification failed: {self:?}")
    }
}
impl Error for IndexError {}

/// Verified compressed bytes have been safely decoded, but Release freshness is unchecked.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedIndex {
    contents: Vec<u8>,
}
impl VerifiedIndex {
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

/// Verify a component index using only SHA256 and size from the signed Release.
pub fn verify_packages_index(
    release: &VerifiedRelease,
    component: &str,
    format: IndexFormat,
    compressed: &[u8],
) -> Result<VerifiedIndex, IndexError> {
    verify_packages_index_with_limits(
        release,
        component,
        format,
        compressed,
        IndexLimits::default(),
    )
}

/// As `verify_packages_index`, with an explicit bounded resource policy.
pub fn verify_packages_index_with_limits(
    release: &VerifiedRelease,
    component: &str,
    format: IndexFormat,
    compressed: &[u8],
    limits: IndexLimits,
) -> Result<VerifiedIndex, IndexError> {
    if !release
        .source()
        .components()
        .iter()
        .any(|item| item == component)
    {
        return Err(IndexError::PolicyMismatch);
    }
    if compressed.len() > limits.compressed {
        return Err(IndexError::TooLarge);
    }
    let suffix = match format {
        IndexFormat::Gzip => "gz",
        IndexFormat::Xz => "xz",
    };
    let path = format!(
        "{component}/binary-{}/Packages.{suffix}",
        release.source().architecture()
    );
    let (expected_size, expected_digest) = lookup_checksum(release.contents(), &path)?;
    if expected_size != compressed.len() as u64
        || Sha256::digest(compressed).as_slice() != expected_digest
    {
        return Err(IndexError::Integrity);
    }
    let contents = decompress(format, compressed, limits.expanded)?;
    Ok(VerifiedIndex { contents })
}

fn lookup_checksum(release: &[u8], wanted: &str) -> Result<(u64, [u8; 32]), IndexError> {
    let text = std::str::from_utf8(release).map_err(|_| IndexError::InvalidMetadata)?;
    let mut inside = false;
    let mut found_section = false;
    let mut result = None;
    let mut entries = std::collections::BTreeSet::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with([' ', '\t']) {
            if !inside {
                continue;
            }
            let mut fields = line.split_ascii_whitespace();
            let hash = fields.next().ok_or(IndexError::InvalidMetadata)?;
            let size = fields.next().ok_or(IndexError::InvalidMetadata)?;
            let path = fields.next().ok_or(IndexError::InvalidMetadata)?;
            if fields.next().is_some()
                || hash.len() != 64
                || !hash.bytes().all(|b| b.is_ascii_hexdigit())
                || path.starts_with('/')
                || path
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == "..")
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._+-@".contains(&b))
                || !entries.insert(path)
                || entries.len() > 32768
            {
                return Err(IndexError::InvalidMetadata);
            }
            let size: u64 = size.parse().map_err(|_| IndexError::InvalidMetadata)?;
            if path == wanted {
                let mut digest = [0u8; 32];
                for (i, byte) in digest.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)
                        .map_err(|_| IndexError::InvalidMetadata)?;
                }
                result = Some((size, digest));
            }
        } else {
            inside = false;
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("SHA256") {
                    if found_section || !value.trim().is_empty() {
                        return Err(IndexError::InvalidMetadata);
                    }
                    found_section = true;
                    inside = true;
                }
            } else if !line.is_empty() {
                return Err(IndexError::InvalidMetadata);
            }
        }
    }
    if !found_section {
        return Err(IndexError::InvalidMetadata);
    }
    result.ok_or(IndexError::InvalidMetadata)
}

#[cfg(not(target_os = "linux"))]
fn decompress(_: IndexFormat, _: &[u8], _: usize) -> Result<Vec<u8>, IndexError> {
    Err(IndexError::HelperUnavailable)
}

#[cfg(target_os = "linux")]
fn decompress(
    format: IndexFormat,
    compressed: &[u8],
    expanded_limit: usize,
) -> Result<Vec<u8>, IndexError> {
    use std::{
        fs,
        io::Read,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir().map_err(|_| IndexError::HelperUnavailable)?;
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, compressed).map_err(|_| IndexError::HelperUnavailable)?;
    let infile = fs::File::open(&input).map_err(|_| IndexError::HelperUnavailable)?;
    let outfile = fs::File::create(&output).map_err(|_| IndexError::HelperUnavailable)?;
    let mut cmd = Command::new("/usr/bin/prlimit");
    cmd.arg(format!("--fsize={expanded_limit}:{expanded_limit}"));
    cmd.args([
        "--as=268435456:268435456",
        "--cpu=15:15",
        "--nofile=64:64",
        "--core=0:0",
        "--",
    ]);
    match format {
        IndexFormat::Gzip => {
            cmd.args(["/usr/bin/gzip", "--decompress", "--stdout"]);
        }
        IndexFormat::Xz => {
            cmd.args([
                "/usr/bin/xz",
                "--format=xz",
                "--memlimit-decompress=67108864",
                "--decompress",
                "--stdout",
            ]);
        }
    }
    cmd.env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::from(infile))
        .stdout(Stdio::from(outfile))
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|_| IndexError::HelperUnavailable)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(IndexError::Decompression);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(IndexError::Decompression);
            }
        }
    };
    if !status.success() {
        return Err(IndexError::Decompression);
    }
    let mut bytes = Vec::new();
    fs::File::open(output)
        .map_err(|_| IndexError::Decompression)?
        .take((expanded_limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| IndexError::Decompression)?;
    if bytes.len() > expanded_limit {
        return Err(IndexError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PATH: &str = "main/binary-amd64/Packages.gz";
    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    #[test]
    fn rejects_ambiguous_or_malformed_signed_sha256_sections() {
        let valid = format!("Suite: bookworm\nSHA256:\n {HASH} 12 {PATH}\n");
        assert_eq!(lookup_checksum(valid.as_bytes(), PATH).unwrap().0, 12);
        let cases = [
            valid.replace(HASH, "1234"),
            valid.replace(" 12 ", " -1 "),
            format!("{valid} {HASH} 12 {PATH}\n"),
            format!("{valid}SHA256:\n {HASH} 12 {PATH}\n"),
            valid.replace(PATH, "../Packages.gz"),
            valid.replace("SHA256:", "SHA1:"),
            valid.replace(PATH, "main/binary-amd64/Packages.xz"),
        ];
        for case in cases {
            assert!(lookup_checksum(case.as_bytes(), PATH).is_err());
        }
    }

    #[test]
    #[ignore = "requires cached Ubuntu noble InRelease on the host"]
    fn parses_real_ubuntu_release_sha256_section() {
        let input =
            std::fs::read("/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble_InRelease")
                .unwrap();
        // Extract the clearsigned text with the verifier in integration tests;
        // this parser test slices the visible control stanza only.
        let text = std::str::from_utf8(&input).unwrap();
        let content = text
            .split_once("\n\n")
            .unwrap()
            .1
            .split_once("\n-----BEGIN PGP SIGNATURE-----")
            .unwrap()
            .0;
        let (size, _) =
            lookup_checksum(content.as_bytes(), "main/binary-amd64/Packages.xz").unwrap();
        assert_eq!(size, 1_401_160);
    }
}
