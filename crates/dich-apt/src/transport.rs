//! Restricted HTTPS download of an authorized artifact.
use crate::artifact::verify_artifact_stream_with_clock;
use crate::{AuthorizedArtifact, VerifiedArtifact};
use std::{
    error::Error,
    fmt,
    io::Read,
    time::{Duration, Instant, SystemTime},
};
use url::Url;

const MAX_REDIRECTS: usize = 5;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, PartialEq, Eq)]
pub enum FetchError {
    InvalidUrl,
    Redirect,
    Status,
    Transport,
    Artifact,
    Timeout,
}
impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "artifact fetch failed: {self:?}")
    }
}
impl Error for FetchError {}

impl HttpsTransport {
    pub(crate) fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .https_only(true)
            .redirects(0)
            .try_proxy_from_env(false)
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .build();
        Self { agent }
    }
}

pub(crate) struct NetworkResponse {
    pub status: u16,
    pub location: Option<String>,
    pub content_length: Option<u64>,
    pub content_encoding: Option<String>,
    pub body: Box<dyn Read>,
}
pub(crate) trait Transport {
    fn request(&mut self, url: &Url, timeout: Duration) -> Result<NetworkResponse, FetchError>;
}
pub(crate) struct HttpsTransport {
    pub(crate) agent: ureq::Agent,
}
impl Transport for HttpsTransport {
    fn request(&mut self, url: &Url, timeout: Duration) -> Result<NetworkResponse, FetchError> {
        let response = match self
            .agent
            .get(url.as_str())
            .set("Accept-Encoding", "identity")
            .timeout(timeout)
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(_) => return Err(FetchError::Transport),
        };
        let one_header = |name: &str| -> Result<Option<String>, FetchError> {
            let values = response.all(name);
            if values.len() > 1 {
                return Err(FetchError::Status);
            }
            Ok(values.first().map(|s| (*s).to_owned()))
        };
        let location = one_header("Location")?;
        let content_encoding = one_header("Content-Encoding")?;
        let content_length = one_header("Content-Length")?
            .map(|s| s.parse::<u64>().map_err(|_| FetchError::Status))
            .transpose()?;
        Ok(NetworkResponse {
            status: response.status(),
            location,
            content_length,
            content_encoding,
            body: response.into_reader(),
        })
    }
}

pub(crate) fn fetch_with_transport(
    authorized: &AuthorizedArtifact,
    max_bytes: u64,
    transport: &mut impl Transport,
    clock: impl Fn() -> SystemTime,
) -> Result<VerifiedArtifact, FetchError> {
    let artifact = authorized.artifact();
    if max_bytes == 0 || artifact.size() > max_bytes {
        return Err(FetchError::Artifact);
    }
    if !authorized.is_valid_at(clock()) {
        return Err(FetchError::Artifact);
    }
    let mut base = Url::parse(artifact.source.uri()).map_err(|_| FetchError::InvalidUrl)?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || base.query().is_some()
        || base.fragment().is_some()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(FetchError::InvalidUrl);
    }
    let path = format!("{}/", base.path().trim_end_matches('/'));
    base.set_path(&path);
    let mut current = base
        .join(artifact.path())
        .map_err(|_| FetchError::InvalidUrl)?;
    if !within_base(&base, &current) {
        return Err(FetchError::InvalidUrl);
    }
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    for redirects in 0..=MAX_REDIRECTS {
        if !authorized.is_valid_at(clock()) {
            return Err(FetchError::Artifact);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(FetchError::Timeout)?;
        let response = transport.request(&current, remaining)?;
        match response.status {
            200 => {
                if response
                    .content_length
                    .is_some_and(|length| length != artifact.size())
                    || response
                        .content_encoding
                        .as_deref()
                        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
                {
                    return Err(FetchError::Status);
                }
                return verify_artifact_stream_with_clock(
                    authorized,
                    response.body,
                    max_bytes,
                    &clock,
                )
                .map_err(|_| FetchError::Artifact);
            }
            301 | 302 | 303 | 307 | 308 if redirects < MAX_REDIRECTS => {
                let location = response.location.as_deref().ok_or(FetchError::Redirect)?;
                current = resolve_redirect(&base, &current, location)?;
            }
            301 | 302 | 303 | 307 | 308 => return Err(FetchError::Redirect),
            _ => return Err(FetchError::Status),
        }
    }
    Err(FetchError::Redirect)
}

fn within_base(base: &Url, target: &Url) -> bool {
    target.scheme() == "https"
        && target.origin() == base.origin()
        && target.username().is_empty()
        && target.password().is_none()
        && target.query().is_none()
        && target.fragment().is_none()
        && !target.path().contains('%')
        && target.path().starts_with(base.path())
}
pub(crate) fn resolve_redirect(
    base: &Url,
    current: &Url,
    location: &str,
) -> Result<Url, FetchError> {
    if location.is_empty()
        || location.len() > 4096
        || !location.is_ascii()
        || location
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b"%\\?#@".contains(&b))
        || location.split('/').any(|part| part == "." || part == "..")
    {
        return Err(FetchError::Redirect);
    }
    let target = current.join(location).map_err(|_| FetchError::Redirect)?;
    if !within_base(base, &target) {
        return Err(FetchError::Redirect);
    }
    Ok(target)
}
