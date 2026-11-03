# ADR 0008 — CLI source loading

Status: Proposed; implementation in progress.

Source policy and deb822 files are local operator-controlled inputs, not authenticated repository data. Open them through bounded, component-wise no-symlink traversal, validating owner and rejecting group/other-writable paths before parsing. List only enabled sources accepted under explicit policy; listing does not assert keyring readability, repository authenticity, freshness or package availability. Missing, unsafe or malformed inputs fail closed without partial output. CLI JSON responses and errors must have a versioned schema. Repository update and cached search must separately verify signed metadata and freshness; listing alone must not initialize cache or change system files.

The initial `sources list` command uses `--config` (default `/etc/dich/sources.toml`) and optional global `--json`. JSON success contains `schema_version: 1`, `status: completed` and a `sources` array whose entries are marked `configured`. JSON failures contain the same schema version, `status: error`, and an error object with a stable `code` and safe message. Listing does not validate the contents of the configured keyring. The remaining repository commands are not implemented.
