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
    FetchRelease(crate::FetchError),
    Freshness(crate::FreshnessError),
    StoreRelease(crate::CacheError),
    IndexFormat(crate::IndexError),
    FetchIndex {
        component: String,
        source: crate::FetchError,
    },
    StoreIndex {
        component: String,
        source: crate::CacheError,
    },
}
impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FetchRelease(error) => write!(
                f,
                "could not fetch or authenticate Release metadata: {error}"
            ),
            Self::Freshness(error) => {
                write!(f, "Release metadata failed freshness validation: {error}")
            }
            Self::StoreRelease(error) => {
                write!(f, "could not store verified Release metadata: {error}")
            }
            Self::IndexFormat(error) => {
                write!(f, "could not select a signed Packages index: {error}")
            }
            Self::FetchIndex { component, source } => write!(
                f,
                "could not fetch or verify Packages index for component {component}: {source}"
            ),
            Self::StoreIndex { component, source } => write!(
                f,
                "could not store verified Packages index for component {component}: {source}"
            ),
        }
    }
}
impl Error for UpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FetchRelease(error) => Some(error),
            Self::Freshness(error) => Some(error),
            Self::StoreRelease(error) => Some(error),
            Self::IndexFormat(error) => Some(error),
            Self::FetchIndex { source, .. } => Some(source),
            Self::StoreIndex { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_error_reports_stage_and_authentication_cause() {
        let error = UpdateError::FetchRelease(crate::FetchError::Authentication(
            crate::SignatureError::UntrustedSigner,
        ));
        let rendered = error.to_string();
        assert!(rendered.contains("Release metadata"));
        assert!(rendered.contains("Authentication(UntrustedSigner)"));
    }

    #[test]
    fn update_error_identifies_component_for_index_failures() {
        let error = UpdateError::FetchIndex {
            component: "main".into(),
            source: crate::FetchError::Index(crate::IndexError::Integrity),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("component main"));
        assert!(rendered.contains("Index(Integrity)"));
    }
}

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
    let mut transport = HttpsTransport::with_proxy(proxy).map_err(UpdateError::FetchRelease)?;
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
        fetch_release_with_transport(source, transport).map_err(UpdateError::FetchRelease)?;
    let fresh = validate_release(&release, clock(), policy).map_err(UpdateError::Freshness)?;
    journal
        .store_release_with_clock(&fresh, FailurePoint::None, &clock)
        .map_err(UpdateError::StoreRelease)?;
    let mut indices = 0;
    for component in source.components() {
        let format = choose_index_format(&fresh, component).map_err(UpdateError::IndexFormat)?;
        let index =
            fetch_index_with_transport(&fresh, component, format, limits, transport, &clock)
                .map_err(|source| UpdateError::FetchIndex {
                    component: component.clone(),
                    source,
                })?;
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
            .map_err(|source| UpdateError::StoreIndex {
                component: component.clone(),
                source,
            })?;
        indices += 1;
    }
    Ok(UpdateReport { indices })
}
