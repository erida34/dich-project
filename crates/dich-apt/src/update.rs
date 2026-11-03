//! Authenticated update of a single explicitly configured source.
use crate::cache::FailurePoint;
use crate::transport::{
    HttpConnectProxy, HttpsTransport, Transport, fetch_index_with_transport,
    fetch_release_with_transport,
};
use crate::{
    FreshnessPolicy, IndexLimits, SnapshotJournal, Source, choose_index_format, validate_release,
};
use std::{error::Error, fmt, time::SystemTime};

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    Fetch,
    Freshness,
    Index,
    Cache,
}
impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "repository update failed: {self:?}")
    }
}
impl Error for UpdateError {}

#[derive(Debug, PartialEq, Eq)]
pub struct UpdateReport {
    pub indices: usize,
}

/// Refresh one source. Errors can leave a newer Release or a subset of indices cached.
pub fn update_source(
    source: &Source,
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    limits: IndexLimits,
) -> Result<UpdateReport, UpdateError> {
    update_with_transport(
        source,
        journal,
        policy,
        limits,
        &mut HttpsTransport::new(),
        SystemTime::now,
    )
}

/// Refresh one source through an explicitly supplied HTTP CONNECT proxy.
pub fn update_source_with_proxy(
    source: &Source,
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    limits: IndexLimits,
    proxy: &HttpConnectProxy,
) -> Result<UpdateReport, UpdateError> {
    let mut transport = HttpsTransport::with_proxy(proxy).map_err(|_| UpdateError::Fetch)?;
    update_with_transport(
        source,
        journal,
        policy,
        limits,
        &mut transport,
        SystemTime::now,
    )
}

pub(crate) fn update_with_transport(
    source: &Source,
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    limits: IndexLimits,
    transport: &mut impl Transport,
    clock: impl Fn() -> SystemTime,
) -> Result<UpdateReport, UpdateError> {
    let release =
        fetch_release_with_transport(source, transport).map_err(|_| UpdateError::Fetch)?;
    let fresh = validate_release(&release, clock(), policy).map_err(|_| UpdateError::Freshness)?;
    journal
        .store_release_with_clock(&fresh, FailurePoint::None, &clock)
        .map_err(|_| UpdateError::Cache)?;
    let mut indices = 0;
    for component in source.components() {
        let format = choose_index_format(&fresh, component).map_err(|_| UpdateError::Index)?;
        let index =
            fetch_index_with_transport(&fresh, component, format, limits, transport, &clock)
                .map_err(|_| UpdateError::Fetch)?;
        journal
            .store_index_with_clock(
                &fresh,
                component,
                format,
                index.compressed(),
                limits,
                FailurePoint::None,
                &clock,
            )
            .map_err(|_| UpdateError::Cache)?;
        indices += 1;
    }
    Ok(UpdateReport { indices })
}
