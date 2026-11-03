# Changelog

## [Unreleased]
- Added authenticated, confirmation-gated profile selection for the narrow signed x86-64 glibc DSO closure; scripts, triggers, unsupported ELF and unverified local inputs remain rejected. Output provides explicit object paths; Dich does not load the code or change host loader state.
- Added package-labelled v3 profile manifests, metadata-only `remove` with a retained inactive pointer, and rollback to a retained prior generation; objects remain stored and GC is not implemented.
- Added `install --exact-version` for selecting a specific authenticated Debian version; signed two-version fixtures verify profile generation switching and CLI rollback.
- Added `dich-engine` as the package orchestration boundary; the CLI remains responsible for argument validation and output, while apt/deb/store crates own trust, compatibility and publication checks.
- Added bounded byte-level ELF inventory for interpreter, SONAME, NEEDED libraries, search paths, direct dynamic-loading imports and required symbol versions; it does not approve compatibility.
- `dich-deb` inspection now reports heuristic path and text indicators for package configuration, services, pkg-config/CMake, NSS/locale, shebangs, absolute path tokens and selected host commands; compatibility analysis remains incomplete.
- `.deb` inspection now associates bounded ELF evidence with archive file paths, including loader, dependency, search-path and symbol-version facts.
- `dich inspect --json` now emits compatibility evidence and conservative `unsupported` or `review_required` status; it does not make packages installable.
- The compatibility report can mark only a single self-contained explicit-path shared-object payload as `supported`; all other package classes remain review-required or unsupported.
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
