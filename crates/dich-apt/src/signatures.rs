//! Isolated gpgv verification. This does not establish metadata freshness or integrity chains.
use std::{error::Error, fmt};

use crate::Source;

const MAX_RELEASE: usize = 4 * 1024 * 1024;
const MAX_KEYRING: usize = 4 * 1024 * 1024;
const MAX_SIGNATURE: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    InvalidInput,
    VerificationFailed,
    UntrustedSigner,
    KeyringAccess,
    HelperUnavailable,
}
impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "repository signature verification failed: {self:?}")
    }
}
impl Error for SignatureError {}

/// Signature-verified bytes only; expiry, identity and checksums are not yet checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    contents: Vec<u8>,
    signing_fingerprint: String,
    signing_fingerprints: Vec<String>,
    source: Source,
    pub(crate) envelope: SignedEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignedEnvelope {
    Inline(Vec<u8>),
    Detached {
        release: Vec<u8>,
        signature: Vec<u8>,
    },
}
impl VerifiedRelease {
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
    pub fn signing_fingerprint(&self) -> &str {
        &self.signing_fingerprint
    }
    /// Every verified signer, in gpgv status order.
    pub fn signing_fingerprints(&self) -> &[String] {
        &self.signing_fingerprints
    }
    /// Source policy under which the signature was verified.
    pub fn source(&self) -> &Source {
        &self.source
    }
}

/// Verify an InRelease using the securely opened keyring named by source policy.
pub fn verify_configured_inrelease(
    source: &Source,
    input: &[u8],
) -> Result<VerifiedRelease, SignatureError> {
    let keyring = crate::read_configured_keyring(source)?;
    verify_inrelease(source, &keyring, input)
}

/// Verify a detached signature using the securely opened configured keyring.
pub fn verify_configured_detached_release(
    source: &Source,
    release: &[u8],
    signature: &[u8],
) -> Result<VerifiedRelease, SignatureError> {
    let keyring = crate::read_configured_keyring(source)?;
    verify_detached_release(source, &keyring, release, signature)
}

/// Internal primitive: the public entry point loads the configured keyring securely.
pub(crate) fn verify_inrelease(
    source: &Source,
    keyring: &[u8],
    input: &[u8],
) -> Result<VerifiedRelease, SignatureError> {
    const BEGIN: &[u8] = b"-----BEGIN PGP SIGNED MESSAGE-----";
    const SIG_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
    const SIG_END: &[u8] = b"-----END PGP SIGNATURE-----";
    if input.len() > MAX_RELEASE
        || !input.starts_with(BEGIN)
        || input.windows(BEGIN.len()).filter(|w| *w == BEGIN).count() != 1
        || input
            .windows(SIG_BEGIN.len())
            .filter(|w| *w == SIG_BEGIN)
            .count()
            != 1
        || input
            .windows(SIG_END.len())
            .filter(|w| *w == SIG_END)
            .count()
            != 1
        || !input.trim_ascii_end().ends_with(SIG_END)
    {
        return Err(SignatureError::InvalidInput);
    }
    verify(source, keyring, input, None)
}

/// Internal primitive: the public entry point loads the configured keyring securely.
pub(crate) fn verify_detached_release(
    source: &Source,
    keyring: &[u8],
    release: &[u8],
    signature: &[u8],
) -> Result<VerifiedRelease, SignatureError> {
    if release.is_empty()
        || release.len() > MAX_RELEASE
        || signature.is_empty()
        || signature.len() > MAX_SIGNATURE
    {
        return Err(SignatureError::InvalidInput);
    }
    verify(source, keyring, release, Some(signature))
}

#[cfg(not(target_os = "linux"))]
fn verify(
    _: &Source,
    _: &[u8],
    _: &[u8],
    _: Option<&[u8]>,
) -> Result<VerifiedRelease, SignatureError> {
    Err(SignatureError::HelperUnavailable)
}

#[cfg(target_os = "linux")]
fn verify(
    source: &Source,
    keyring: &[u8],
    input: &[u8],
    signature: Option<&[u8]>,
) -> Result<VerifiedRelease, SignatureError> {
    use std::{
        fs,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    if keyring.is_empty() || keyring.len() > MAX_KEYRING {
        return Err(SignatureError::InvalidInput);
    }
    let dir = tempfile::tempdir().map_err(|_| SignatureError::HelperUnavailable)?;
    let key_path = dir.path().join("keys.gpg");
    let input_path = dir.path().join("input");
    let signature_path = dir.path().join("signature");
    let output_path = dir.path().join("plain");
    let status_path = dir.path().join("status");
    fs::write(&key_path, keyring).map_err(|_| SignatureError::HelperUnavailable)?;
    fs::write(&input_path, input).map_err(|_| SignatureError::HelperUnavailable)?;
    if let Some(signature) = signature {
        fs::write(&signature_path, signature).map_err(|_| SignatureError::HelperUnavailable)?;
    }
    let status_file =
        fs::File::create(&status_path).map_err(|_| SignatureError::HelperUnavailable)?;
    // Both executables are fixed system paths. prlimit enforces per-file, address-space,
    // CPU and descriptor ceilings before exec; absence or failure is fatal.
    let mut cmd = Command::new("/usr/bin/prlimit");
    cmd.args([
        "--fsize=8388608:8388608",
        "--as=536870912:536870912",
        "--cpu=10:10",
        "--nofile=64:64",
        "--core=0:0",
        "--",
        "/usr/bin/gpgv",
    ]);
    cmd.env_clear()
        .env("LC_ALL", "C")
        .arg("--homedir")
        .arg(dir.path())
        .arg("--keyring")
        .arg(&key_path)
        .args([
            "--status-fd",
            "1",
            "--weak-digest",
            "SHA1",
            "--weak-digest",
            "MD5",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(status_file))
        .stderr(Stdio::null());
    if signature.is_some() {
        cmd.arg("--").arg(&signature_path).arg(&input_path);
    } else {
        cmd.arg("--output")
            .arg(&output_path)
            .arg("--")
            .arg(&input_path);
    }
    let mut child = cmd.spawn().map_err(|_| SignatureError::HelperUnavailable)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        let too_large = fs::metadata(&status_path)
            .map(|m| m.len() > 256 * 1024)
            .unwrap_or(false)
            || fs::metadata(&output_path)
                .map(|m| m.len() > MAX_RELEASE as u64)
                .unwrap_or(false);
        if too_large || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SignatureError::VerificationFailed);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SignatureError::VerificationFailed);
            }
        }
    };
    if !status.success() {
        return Err(SignatureError::VerificationFailed);
    }
    let status_bytes = read_bounded(&status_path, 256 * 1024)?;
    let signers = parse_status(source, &status_bytes)?;
    let signer = signers
        .first()
        .cloned()
        .ok_or(SignatureError::VerificationFailed)?;
    let contents = if signature.is_some() {
        input.to_vec()
    } else {
        read_bounded(&output_path, MAX_RELEASE)?
    };
    if contents.is_empty() || contents.len() > MAX_RELEASE {
        return Err(SignatureError::VerificationFailed);
    }
    Ok(VerifiedRelease {
        contents,
        signing_fingerprint: signer,
        signing_fingerprints: signers,
        source: source.clone(),
        envelope: match signature {
            Some(signature) => SignedEnvelope::Detached {
                release: input.to_vec(),
                signature: signature.to_vec(),
            },
            None => SignedEnvelope::Inline(input.to_vec()),
        },
    })
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &std::path::Path, limit: usize) -> Result<Vec<u8>, SignatureError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| SignatureError::VerificationFailed)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SignatureError::VerificationFailed)?;
    if bytes.len() > limit {
        return Err(SignatureError::VerificationFailed);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn parse_status(source: &Source, bytes: &[u8]) -> Result<Vec<String>, SignatureError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SignatureError::VerificationFailed)?;
    let mut signers = Vec::new();
    let mut in_signature = false;
    let mut good = false;
    let mut valid = false;
    for line in text.lines() {
        let line = line
            .strip_prefix("[GNUPG:] ")
            .ok_or(SignatureError::VerificationFailed)?;
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        match fields.first().copied() {
            Some("VALIDSIG") if fields.len() == 11 && in_signature && good && !valid => {
                if !matches!(fields[8], "8" | "9" | "10" | "11") {
                    return Err(SignatureError::VerificationFailed);
                }
                let (signer, primary) = (fields[1], fields[10]);
                let allowed = source.fingerprints().iter().any(|allowed| {
                    if let Some(exact) = allowed.strip_suffix('!') {
                        exact == signer
                    } else {
                        allowed == signer || allowed == primary
                    }
                });
                if !allowed {
                    return Err(SignatureError::UntrustedSigner);
                }
                if signers.iter().any(|previous| previous == signer) {
                    return Err(SignatureError::VerificationFailed);
                }
                signers.push(signer.to_owned());
                valid = true;
            }
            Some("NEWSIG") => {
                if in_signature && (!good || !valid) {
                    return Err(SignatureError::VerificationFailed);
                }
                in_signature = true;
                good = false;
                valid = false;
            }
            Some("GOODSIG") if in_signature && !good && !valid => good = true,
            Some("PLAINTEXT" | "KEY_CONSIDERED" | "SIG_ID") => (),
            _ => return Err(SignatureError::VerificationFailed),
        }
    }
    if !in_signature || !good || !valid || signers.is_empty() {
        return Err(SignatureError::VerificationFailed);
    }
    Ok(signers)
}
