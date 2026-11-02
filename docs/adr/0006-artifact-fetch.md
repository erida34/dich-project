# ADR 0006 — Artifact identity and fetch boundary

Status: Proposed; implementation in progress.

Derive artifact identity only from a `VerifiedIndex` that retains the source policy used to authenticate its Release. Select an exact package name and version, require matching configured architecture or `all`, and reject duplicate matching records, unsafe relative paths, absent SHA256 or size, and excessive size. Paths are restricted to relative `pool/` `.deb` paths with no URL escapes or traversal. A selected record is metadata, not a downloaded, verified, extracted or installable package.

The library validates signed Origin, Suite/Codename, Date and Valid-Until against explicit operator maximum age, clock skew and whether Valid-Until is required. Omitting Valid-Until is permitted only under an explicit nonzero maximum age. Artifact authorization binds the selected record to the identical verified Release digest and source; the stream verifier checks freshness before and after reading and compares exact size and SHA256 before returning an anonymous temporary file. This assumes a trusted clock and does not yet persist anti-rollback state.

Network fetch must use structured HTTPS requests and a restrictive redirect policy, bounded streaming to safe temporary storage, and compare the complete byte count and SHA256 before publishing any durable artifact. Bind redirects to explicit configured origin policy; never interpolate paths into shell commands or disable TLS checks. Reject rollback/freeze where the necessary prior state exists. Account for crash safety and concurrent cache updates in the subsequent cache milestone. Network transport, persisted rollback detection and durable publishing are not yet implemented.
