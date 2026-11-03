//! Read package metadata only after the cache reauthenticates its signed source.
use crate::{
    DebianVersion, FreshnessPolicy, IndexLimits, SnapshotJournal, Source, choose_index_format,
    parse_control_stanzas,
};
use std::{error::Error, fmt, time::SystemTime};

#[derive(Debug, Clone, Copy)]
pub enum Query<'a> {
    Search(&'a str),
    Show(&'a str),
    Versions(&'a str),
}
#[derive(Debug, PartialEq, Eq)]
pub enum QueryError {
    InvalidQuery,
    Cache,
    Metadata,
    TooManyResults,
}
impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cached query failed: {self:?}")
    }
}
impl Error for QueryError {}
#[derive(Debug, PartialEq, Eq)]
pub struct PackageRecord {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub source: String,
    pub suite: String,
}

/// Read complete configured sources from cache; missing or stale data is an error, not partial success.
pub fn query_cached(
    sources: &[Source],
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    query: Query<'_>,
) -> Result<Vec<PackageRecord>, QueryError> {
    query_with_clock(sources, journal, policy, query, SystemTime::now)
}
pub(crate) fn query_with_clock(
    sources: &[Source],
    journal: &SnapshotJournal,
    policy: FreshnessPolicy,
    query: Query<'_>,
    clock: impl Fn() -> SystemTime,
) -> Result<Vec<PackageRecord>, QueryError> {
    let input = match query {
        Query::Search(s) | Query::Show(s) | Query::Versions(s) => s,
    };
    if input.is_empty()
        || input.len() > 128
        || !input
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
    {
        return Err(QueryError::InvalidQuery);
    }
    let mut records: Vec<(PackageRecord, DebianVersion)> = Vec::new();
    for source in sources {
        let release = journal
            .load_release_with_clock(source, policy, &clock)
            .map_err(|_| QueryError::Cache)?;
        for component in source.components() {
            let format =
                choose_index_format(&release, component).map_err(|_| QueryError::Metadata)?;
            let (indexed_release, index) = journal
                .load_index_with_clock(
                    source,
                    policy,
                    component,
                    format,
                    IndexLimits::default(),
                    &clock,
                )
                .map_err(|_| QueryError::Cache)?;
            if indexed_release.release().contents() != release.release().contents() {
                return Err(QueryError::Cache);
            }
            let stanzas =
                parse_control_stanzas(index.contents()).map_err(|_| QueryError::Metadata)?;
            for stanza in stanzas {
                let name = stanza.get("package").ok_or(QueryError::Metadata)?;
                let matches = match query {
                    Query::Search(_) => name.contains(input),
                    Query::Show(_) | Query::Versions(_) => name == input,
                };
                if !matches {
                    continue;
                }
                if name.len() > 128
                    || !name.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b)
                    })
                {
                    return Err(QueryError::Metadata);
                }
                let version = stanza.get("version").ok_or(QueryError::Metadata)?;
                let parsed = DebianVersion::parse(version).map_err(|_| QueryError::Metadata)?;
                let architecture = stanza.get("architecture").ok_or(QueryError::Metadata)?;
                if architecture != "all" && architecture != source.architecture() {
                    return Err(QueryError::Metadata);
                }
                if records.len() >= 10000 {
                    return Err(QueryError::TooManyResults);
                }
                records.push((
                    PackageRecord {
                        name: name.into(),
                        version: version.into(),
                        architecture: architecture.into(),
                        source: source.uri().into(),
                        suite: source.suite().into(),
                    },
                    parsed,
                ));
            }
        }
    }
    records.sort_by(|(a, av), (b, bv)| {
        a.name
            .cmp(&b.name)
            .then_with(|| bv.cmp(av))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.suite.cmp(&b.suite))
            .then_with(|| a.version.cmp(&b.version))
    });
    Ok(records.into_iter().map(|(record, _)| record).collect())
}
