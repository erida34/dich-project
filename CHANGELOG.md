# Changelog

## [Unreleased]
- Added bounded byte-level ELF inventory for interpreter, SONAME, NEEDED libraries, search paths, direct dynamic-loading imports and required symbol versions; it does not approve compatibility.
- `dich-deb` inspection now reports heuristic path and text indicators for package configuration, services, pkg-config/CMake, NSS/locale, shebangs, absolute path tokens and selected host commands; compatibility analysis remains incomplete.
- `.deb` inspection now associates bounded ELF evidence with archive file paths, including loader, dependency, search-path and symbol-version facts.
- `dich inspect --json` now emits compatibility evidence and conservative `unsupported` or `review_required` status; it does not make packages installable.
- `update` and `fetch` accept an explicit credential-free HTTP CONNECT proxy URL; TLS certificate and signed repository metadata checks remain enabled.
- Authenticated repository metadata update and offline package-name, version and source queries; experimental exact-version `fetch` downloads or revalidates a cached artifact and can explicitly publish a conservative tree without installing.
- Added an explicit resolver release and architecture policy model; no resolver or installation is implemented.
- Added package relationship metadata models; dependency resolution is not implemented.
- Added a narrow single-source metadata-only planning prototype; resulting plans are not installable or artifact locks.
- Metadata plans include source, signed Release and artifact digest identities; lock replay is not implemented.
- Explicit deny-all execution admission for unexamined or unsupported package actions.
- Added bounded, read-only Debian archive inspection for uncompressed, gzip, xz and zstd members; `dich inspect` labels local archives unverified and does not extract or execute them.
- Added Linux-only private staging of verified cached artifacts with conservative archive and path rejection; no store activation.
- Record known maintainer script hashes and trigger-file presence without executing scripts.
- Added source-bound canonical store identity derivation; exact reuse rechecks stored content.
- Added an experimental protected SQLite WAL/FULL metadata store and exclusive locking.
- Prototype publication of verified raw archives and private staged trees with bounded manual recovery; process interruptions are tested, but physical power-loss durability and activation remain unverified.
- Experimental contextual dependency graph snapshots, metadata-only object inspection and local-content verification; `store ls` and `store verify` operate only on existing current-schema stores. No GC roots or activation.
- Debian packaging declares required verification/decompression helpers; release workflow pins action commits and checks man pages and completions on Debian and Ubuntu. Hosted release remains unverified.
- Project definition, developer guide, Rust workspace stub, documentation and release-pipeline scaffold.
