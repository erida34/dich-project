# Changelog

## [Unreleased]
- Authenticated repository metadata update and offline package-name, version and source queries; installation remains unsupported.
- Added an explicit resolver release and architecture policy model; no resolver or installation is implemented.
- Added package relationship metadata models; dependency resolution is not implemented.
- Added a narrow single-source metadata-only planning prototype; resulting plans are not installable or artifact locks.
- Metadata plans include source, signed Release and artifact digest identities; lock replay is not implemented.
- Explicit deny-all execution admission for unexamined or unsupported package actions.
- Project definition, developer guide, Rust workspace stub, documentation and release-pipeline scaffold.
