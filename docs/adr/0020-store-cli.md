# ADR 0020 — Store CLI read boundary

Status: Accepted for the experimental Linux store-read subset.

`store ls` and `store verify` operate on an explicitly selected existing protected store. They must never initialize a missing store, accept an initialization marker, or migrate an older schema implicitly. The existing exclusive lock still protects SQLite inspection; opening an existing WAL database may require SQLite sidecars and is not an offline forensic read-only mount. Listing reports local metadata only, while verification separately checks stored bytes against local metadata and explicitly does not reauthenticate repository signatures or prove package compatibility. Verify selects an exact object identity and object kind, fails nonzero for missing or altered data, and never activates content. `--json` uses the existing schema version and explicit status.

Acceptance requires fixture-first end-to-end CLI tests for missing/uninitialized stores, metadata-only listing, invalid identity, corrupted files, JSON errors, and concurrent locking. No command may initialize state or silently upgrade the database as a side effect of inspection. Local `.deb` inspection and authenticated exact-version fetch will be specified separately before implementation.
