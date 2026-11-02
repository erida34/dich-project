//! Signed Release origin, suite and time checks. Rollback state is not implemented.
use crate::{Distribution, VerifiedRelease, parse_control_stanzas};
use chrono::DateTime;
use std::{
    error::Error,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessError {
    InvalidPolicy,
    InvalidMetadata,
    WrongOriginOrSuite,
    NotYetValid,
    Expired,
    Clock,
}
impl fmt::Display for FreshnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Release validation failed: {self:?}")
    }
}
impl Error for FreshnessError {}

/// Explicit maximum age and clock-skew policy. A trusted clock is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessPolicy {
    max_age: Duration,
    future_skew: Duration,
    require_valid_until: bool,
}
impl FreshnessPolicy {
    pub fn new(
        max_age: Duration,
        future_skew: Duration,
        require_valid_until: bool,
    ) -> Result<Self, FreshnessError> {
        if max_age.is_zero()
            || max_age > Duration::from_secs(10 * 366 * 86400)
            || future_skew > Duration::from_secs(86400)
        {
            return Err(FreshnessError::InvalidPolicy);
        }
        Ok(Self {
            max_age,
            future_skew,
            require_valid_until,
        })
    }
}

/// Signed Release validated for its source and time, without anti-rollback state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRelease {
    release: VerifiedRelease,
    validated_at: SystemTime,
    expires_at: SystemTime,
}
impl ValidatedRelease {
    pub(crate) fn release(&self) -> &VerifiedRelease {
        &self.release
    }
    pub fn source(&self) -> &crate::Source {
        self.release.source()
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    /// Time must not move backwards relative to the initial validation.
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        now >= self.validated_at && now < self.expires_at
    }
}

/// Check source identity and freshness at a caller-provided trusted time.
pub fn validate_release(
    release: &VerifiedRelease,
    now: SystemTime,
    policy: FreshnessPolicy,
) -> Result<ValidatedRelease, FreshnessError> {
    let stanzas =
        parse_control_stanzas(release.contents()).map_err(|_| FreshnessError::InvalidMetadata)?;
    if stanzas.len() != 1 {
        return Err(FreshnessError::InvalidMetadata);
    }
    let stanza = &stanzas[0];
    let origin = match release.source().distribution() {
        Distribution::Debian => "Debian",
        Distribution::Ubuntu => "Ubuntu",
    };
    if stanza.get("origin") != Some(origin)
        || !(stanza.get("suite") == Some(release.source().suite())
            || stanza.get("codename") == Some(release.source().suite()))
    {
        return Err(FreshnessError::WrongOriginOrSuite);
    }
    let date = parse_date(stanza.get("date").ok_or(FreshnessError::InvalidMetadata)?)?;
    let now_seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FreshnessError::Clock)?
        .as_secs();
    if date > now_seconds.saturating_add(policy.future_skew.as_secs()) {
        return Err(FreshnessError::NotYetValid);
    }
    let age_deadline = date
        .checked_add(policy.max_age.as_secs())
        .ok_or(FreshnessError::InvalidMetadata)?;
    let deadline = match stanza.get("valid-until") {
        Some(value) => {
            let until = parse_date(value)?;
            if until <= date {
                return Err(FreshnessError::InvalidMetadata);
            }
            until.min(age_deadline)
        }
        None if policy.require_valid_until => return Err(FreshnessError::InvalidMetadata),
        None => age_deadline,
    };
    if now_seconds >= deadline {
        return Err(FreshnessError::Expired);
    }
    let expires_at = UNIX_EPOCH
        .checked_add(Duration::from_secs(deadline))
        .ok_or(FreshnessError::Clock)?;
    Ok(ValidatedRelease {
        release: release.clone(),
        validated_at: now,
        expires_at,
    })
}

fn parse_date(value: &str) -> Result<u64, FreshnessError> {
    // Debian Release uses UTC; RFC 2822 numeric offsets and GMT are also supported.
    let normalized = if let Some(base) = value.strip_suffix(" UTC") {
        format!("{base} +0000")
    } else {
        value.to_owned()
    };
    let date =
        DateTime::parse_from_rfc2822(&normalized).map_err(|_| FreshnessError::InvalidMetadata)?;
    u64::try_from(date.timestamp()).map_err(|_| FreshnessError::InvalidMetadata)
}
