# ADR 0006 — Artifact identity and fetch boundary

Status: Proposed; implementation in progress.

Derive artifact identity only from a `VerifiedIndex` that retains the source policy used to authenticate its Release. Select an exact package name and version, require matching configured architecture or `all`, and reject duplicate matching records, unsafe relative paths, absent SHA256 or size, and excessive size. Paths are restricted to relative `pool/` `.deb` paths with no URL escapes or traversal. A selected record is metadata, not a downloaded, verified, extracted or installable package.

Network fetch must use structured HTTPS requests and a restrictive redirect policy, bounded streaming to safe temporary storage, and compare the complete byte count and SHA256 before publishing any durable artifact. Bind redirects to explicit configured origin policy; never interpolate paths into shell commands or disable TLS checks. Enforce signed Release suite and freshness policy before network use, including a documented rule for archives without `Valid-Until`; reject rollback/freeze where the necessary prior state exists. Account for crash safety and concurrent cache updates in the subsequent cache milestone. These steps are not yet implemented.
