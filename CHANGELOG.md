# Changelog

## [Unreleased]
- Authenticated repository metadata update and offline package-name, version and source queries; installation remains unsupported.
- Added an explicit resolver release and architecture policy model; no resolver or installation is implemented.
- Added package relationship metadata models; dependency resolution is not implemented.
- Added a narrow single-source metadata-only planning prototype; resulting plans are not installable or artifact locks.
- Metadata plans include source, signed Release and artifact digest identities; lock replay is not implemented.
- Explicit deny-all execution admission for unexamined or unsupported package actions.
- Added bounded, read-only Debian archive inspection for uncompressed, gzip, xz and zstd members; no extraction.
- Added Linux-only private staging of verified cached artifacts with conservative archive and path rejection; no store activation.
- Record known maintainer script hashes and trigger-file presence without executing scripts.
- Added source-bound canonical store identity derivation; persistence and deduplication are not implemented.
- Project definition, developer guide, Rust workspace stub, documentation and release-pipeline scaffold.
