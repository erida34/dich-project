//! Exact artifact download through authenticated cached Release and Packages metadata.
use crate::cache::{CacheError, FailurePoint};
use crate::transport::{HttpConnectProxy, HttpsTransport, Transport};
use crate::{
    AuthorizedArtifact, FreshnessPolicy, IndexLimits, IndexedArtifact, SnapshotJournal, Source,
    authorize_artifact, choose_index_format, select_indexed_artifact,
};
use std::{error::Error, fmt, time::SystemTime};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchExactError {
    Metadata,
    Artifact,
    Cache,
    Offline,
}
impl fmt::Display for FetchExactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exact artifact fetch failed: {self:?}")
    }
}
impl Error for FetchExactError {}
#[derive(Debug, Clone, Copy)]
pub struct FetchRequest<'a> {
    pub component: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub max_bytes: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchState {
    Downloaded,
    Cached,
}
#[derive(Debug)]
pub struct FetchResult {
    authorization: AuthorizedArtifact,
    pub state: FetchState,
}
impl FetchResult {
    pub fn artifact(&self) -> &IndexedArtifact {
        self.authorization.artifact()
    }

    /// Authorization must still be revalidated by each subsequent operation.
    pub fn authorization(&self) -> &AuthorizedArtifact {
        &self.authorization
    }
}
/// Reuse a revalidated cached artifact or download it into the protected verified cache.
pub fn fetch_exact(
    source: &Source,
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    request: FetchRequest<'_>,
) -> Result<FetchResult, FetchExactError> {
    fetch_exact_with_transport(
        source,
        journal,
        policy,
        request,
        &mut HttpsTransport::new(),
        SystemTime::now,
    )
}

/// Fetch one exact package through an explicitly supplied HTTP CONNECT proxy.
pub fn fetch_exact_with_proxy(
    source: &Source,
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    request: FetchRequest<'_>,
    proxy: &HttpConnectProxy,
) -> Result<FetchResult, FetchExactError> {
    let mut transport = HttpsTransport::with_proxy(proxy).map_err(|_| FetchExactError::Artifact)?;
    fetch_exact_with_transport(
        source,
        journal,
        policy,
        request,
        &mut transport,
        SystemTime::now,
    )
}

/// Fetch one exact package without making any network requests.
/// Succeeds only if the requested artifact is already present in the protected cache.
pub fn fetch_exact_offline(
    source: &Source,
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    request: FetchRequest<'_>,
) -> Result<FetchResult, FetchExactError> {
    fetch_exact_with_transport(
        source,
        journal,
        policy,
        request,
        &mut crate::transport::OfflineTransport,
        SystemTime::now,
    )
}

pub(crate) fn fetch_exact_with_transport(
    source: &Source,
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    request: FetchRequest<'_>,
    transport: &mut impl Transport,
    clock: impl Fn() -> SystemTime + Copy,
) -> Result<FetchResult, FetchExactError> {
    if request.max_bytes == 0 || request.max_bytes > 256 * 1024 * 1024 {
        return Err(FetchExactError::Artifact);
    }
    let release = journal
        .load_release_with_clock(source, policy, clock)
        .map_err(|_| FetchExactError::Metadata)?;
    let format =
        choose_index_format(&release, request.component).map_err(|_| FetchExactError::Metadata)?;
    let (release, index) = journal
        .load_index_with_clock(
            source,
            policy,
            request.component,
            format,
            IndexLimits::default(),
            clock,
        )
        .map_err(|_| FetchExactError::Metadata)?;
    let artifact = select_indexed_artifact(&index, request.name, request.version)
        .map_err(|_| FetchExactError::Metadata)?;
    let authorized =
        authorize_artifact(&release, &artifact, clock()).map_err(|_| FetchExactError::Metadata)?;
    if artifact.size() > request.max_bytes {
        return Err(FetchExactError::Artifact);
    }
    match journal.load_artifact_with_clock(&authorized, clock) {
        Ok(_) => {
            return Ok(FetchResult {
                authorization: authorized,
                state: FetchState::Cached,
            });
        }
        Err(CacheError::NotFound) => {}
        Err(_) => return Err(FetchExactError::Cache),
    }
    let verified = journal
        .fetch_with_transport(&authorized, request.max_bytes, transport, clock)
        .map_err(|e| match e {
            CacheError::Fetch(crate::transport::FetchError::Offline) => FetchExactError::Offline,
            _ => FetchExactError::Artifact,
        })?;
    journal
        .store_artifact_with_clock(&authorized, verified, FailurePoint::None, clock)
        .map_err(|_| FetchExactError::Cache)?;
    journal
        .load_artifact_with_clock(&authorized, clock)
        .map_err(|_| FetchExactError::Cache)?;
    Ok(FetchResult {
        authorization: authorized,
        state: FetchState::Downloaded,
    })
}
