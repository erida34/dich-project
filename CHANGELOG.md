# Changelog

All notable changes to Dich will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.8] - 2026-11-04

### Fixed
- Preserve the failing update stage and classified cause in CLI diagnostics, including Release authentication, freshness, index verification and cache writes.

## [0.7.7] - 2026-11-04

### Added
- Debian package configuration prompt and `dich setup` for the pinned official Debian/Ubuntu archive defaults on supported amd64 releases. Noninteractive installs use the safe default; existing configuration is not overwritten.
- A 24-hour default Release freshness window, so ordinary `dich update` needs no policy flags; signed `Valid-Until` is still enforced when present (ADR 0042).

### Fixed
- Clarify that first-run source setup is available starting with version 0.7.4; version 0.7.3 does not include the setup command or installation prompt.
- Use suite-specific regular Debian keyring files: Bookworm's `debian-archive-bookworm-stable.gpg` and Trixie's `debian-archive-keyring.pgp`; the generic Trixie `.gpg` path is a symlink that Dich correctly rejects.
- Install Debian or Ubuntu archive keyrings in the corresponding release smoke-test containers before checking automatic source configuration.

## [0.7.3] - 2026-11-04

### Added
- Russian CLI help and command man pages, selectable with `--lang ru` or `DICH_LANG=ru`; mapped human-readable diagnostics are translated while JSON and normal command output retain their existing English contract.

### Fixed
- Preserve Russian man pages and their parent directories during package installation on Debian and Ubuntu; smoke-test the installed Russian help output.

## [0.7.0] - 2026-11-04

### Changed
- Aligned workspace crates and `Cargo.lock` to `0.7.0`, matching this release and the tag workflow's version check.
- Expanded the tag release smoke gate to all four supported Debian/Ubuntu amd64 releases using pinned OCI manifest digests, including reinstall and removal checks.

### Security
- Fixed the locked `url` dependency after `cargo audit` identified vulnerable `idna 0.5.0`; corrected `cargo-deny` advisory configuration and scoped the webpki certificate-data license exception with its text included in the `.deb`.
- Replaced the hand-authored release SBOM with SPDX 2.3 generated from the locked Cargo dependency graph; release checksums cover the `.deb` and SBOM.

### Added
- **Hardening and Operational Quality (Phase 6)**:
  - **Structured Logging & Diagnostics (ADR 0031)**: Added credential redaction (`dich_core::redact_sensitive`) for URL userinfo, bearer/authorization tokens, and private keys. Standardized numeric exit codes (0–5), diagnostic hints in error payloads, `--log-level` flag, and stderr/stdout separation.
  - **Rootless Development Mode (ADR 0032)**: Confined unprivileged operations to XDG directories (`$XDG_DATA_HOME/dich`, `$XDG_CACHE_HOME/dich`, `$XDG_CONFIG_HOME/dich`). Added `--rootless` and `--system` flags, descriptor-relative directory creation with mode 0700 and parent ownership checks, and user namespace support. Explicitly rejected background daemons and setuid binaries.
  - **Network Hardening & Limits (ADR 0033)**: Added exponential backoff retries on transient network errors (HTTP 429, 502, 503, 504, I/O timeouts), bandwidth pacing via `RateLimitedReader` (`--max-bandwidth`), preflight disk capacity checks via `statvfs(3)` (50 MB minimum), and strict `--offline` mode (`OfflineTransport`) allowing operations only against cached artifacts.
  - **Security Review & TOCTOU Audit (ADR 0034)**: Formally audited key handling, descriptor-relative filesystem traversal (`openat2` with `RESOLVE_BENEATH`), atomic file/directory renames (`renameat2`), hardlink/symlink attack rejection on metadata database and lock files, path traversal rejection, and process limits (`prlimit`).
  - **Performance Benchmarks & Budgets (ADR 0035)**: Added benchmark suite `crates/dich-cli/benches/performance_benchmarks.rs` (`cargo bench -p dich-cli`) and regression tests verifying cold metadata sync (<= 500ms), warm metadata cache revalidation (<= 40ms), package deduplication lookup (<= 5ms), and GC dry-run sweep (<= 50ms).
  - **Distribution Support Matrix (ADR 0036)**: Documented Tier 1 supported platforms (Debian 12 `bookworm`, Debian 13 `trixie`, Ubuntu 22.04 LTS `jammy`, Ubuntu 24.04 LTS `noble` on `amd64`) in `docs/support-matrix.md`. Added adversarial integration tests enforcing rejection of moving suite aliases (`sid`, `unstable`), foreign architectures, cross-distribution mixing, and cross-suite mixing.

- **Profiles, Transactions, and Garbage Collection (Phase 5)**:
  - **Atomic Profile Generations (ADR 0028)**: Package-labelled v3 profile manifests managed via atomic relative symlink switches (`profiles/<name>/current`).
  - **Authenticated DSO Profile Installation (ADR 0029)**: `dich install` and `dich remove` for allowlisted x86-64 glibc DSO closures. `install` plans by default and requires `--yes` confirmation. `dich rollback` atomically reverts to retained parent generations. Verified runtime execution of installed signed paths via isolated link-map namespaces (`dlmopen`).
  - **Mark-and-Sweep Garbage Collection (ADR 0030)**: `dich gc` traverses active profiles and complete rollback chains (`previous_id`) plus explicit pins during root mark phase. Defaults to `--dry-run`; `--execute` removes unreachable store tree objects using descriptor-relative non-symlink traversal with directory fsync and transactional SQLite metadata deletion.

- **ELF and Compatibility Evidence (Phase 4)**:
  - Bounded ELF inspection with Goblin for loader, SONAME, NEEDED dependencies, search paths, and symbol versions (ADR 0022).
  - Package integration heuristics scanning for configuration files, systemd service units, pkg-config, CMake, NSS, locales, shebangs, absolute paths, and host commands (ADR 0023).
  - Machine-readable compatibility report emitted by `dich inspect --json` with conservative `supported`, `unsupported`, or `review_required` statuses (ADR 0024).
  - Standalone DSO allowlist and multi-package closure inspection via `dich inspect --with` (ADR 0025, ADR 0027).

- **Store Durability and Identity (Phase 3)**:
  - Bounded `.deb` archive reading supporting uncompressed, gzip, xz, and zstd formats under resource limits (ADR 0014).
  - Linux private staging using `openat2` beneath-root constraints (ADR 0015).
  - Script metadata inventory recording maintainer script hashes and triggers without execution (ADR 0016).
  - Content-derived canonical store identity manifests (ADR 0017).
  - Protected SQLite WAL/FULL store metadata foundation and exclusive flock concurrency serialization (ADR 0018).

- **Dependencies, Release Policy, and Planning (Phase 2)**:
  - Release architecture policy rejecting moving suite aliases and multi-distro mixing (ADR 0009).
  - Bounded control stanzas and Debian relationship modeling (`Depends`, `Pre-Depends`, `Conflicts`, `Breaks`, `Provides`, `Multi-Arch`) (ADR 0010).
  - Deterministic backtracking dependency resolver and `dich plan` command (ADR 0011).
  - Deny-all execution admission boundary rejecting unsupported package actions (ADR 0013).

- **Repository Trust and Signatures (Phase 1)**:
  - deb822 source policy import and operator configuration (ADR 0002).
  - OpenPGP signature verification via sandboxed `gpgv` under `prlimit` bounds (ADR 0003).
  - Bounded Packages index decompression and hash verification against signed Release (ADR 0004).
  - HTTPS-only transport with rustls and certificate validation (ADR 0006).
  - Protected `SnapshotJournal` cache with rollback protection (ADR 0007).
  - Explicit HTTP CONNECT proxy support without ambient environment discovery (ADR 0021).
