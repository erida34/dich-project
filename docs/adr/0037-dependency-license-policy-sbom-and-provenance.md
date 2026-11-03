# ADR 0037 — Dependency, License, Reproducible Builds, SBOM, and Provenance Policies

Status: Accepted for Phase 7 public release.

## Context

Shipping Dich as a production-grade Linux package store requires verifiable software supply chain security:
- Third-party dependencies must be free of known security vulnerabilities and unmaintained code.
- License obligations must be strictly checked to prevent license pollution or copyleft viral restrictions.
- Binaries must be independently reproducible from source.
- Release artifacts must include cryptographic provenance attestations and standardized SBOMs.

The project roadmap requires:
> cargo-deny, cargo-audit, dependency/license policy, reproducible build guidance, SBOM and provenance.

## Decision

### 1. Automated Supply Chain Auditing
- Introduce `deny.toml` configured to deny known vulnerabilities, unmaintained/unsound crates, non-permissive licenses, wildcard dependencies, and unapproved registries.
- Introduce `audit.toml` configured for `cargo-audit` vulnerability scanning against the RustSec Advisory Database.
- Add `cargo-deny` and `cargo-audit` checks to `.github/workflows/ci.yml`.
- Install both audit CLIs at locked versions in CI and release jobs rather than relying on action images that bundle parsers which may lag the RustSec advisory format.
- Generate SPDX 2.3 from the locked `dich-cli` dependency graph with pinned `cargo-sbom`; package facts must not be hardcoded to a sample version.

### 2. Permissive License Standard
- Dich's own source and documentation are licensed exclusively under Apache-2.0. The dependency allowlist below describes third-party components only and does not offer a second license for Dich.
- All runtime dependencies must adhere to permissive OSI licenses (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`), except Mozilla root-certificate data in the exact locked `webpki-roots` versions. That data uses `CDLA-Permissive-2.0`; its license text ships in the Dich `.deb`, and no other crate is granted this exception.
- Copyleft licenses (GPL, LGPL, AGPL) are strictly forbidden in Dich binaries and libraries.

### 3. Reproducible Build Standard
- Document exact reproducible build steps in `docs/dependency-and-license-policy.md`:
  - `SOURCE_DATE_EPOCH` environment variable for timestamp pinning.
  - `--remap-path-prefix` compiler flags to eliminate host filesystem path leaks.
  - Mandatory `--locked` flag for deterministic dependency resolution.

### 4. SBOM and Cryptographic Build Provenance
- Release workflows in `.github/workflows/release.yml` will produce:
  - `SHA256SUMS` manifest of all release artifacts.
  - Software Bill of Materials (SBOM) in SPDX JSON format.
  - Signed build provenance attestations using `actions/attest-build-provenance` conforming to SLSA standards.
- The SPDX SBOM is generated from the Cargo graph and is checksummed with the `.deb`; the hosted release output remains unverified until the tag workflow runs.

## Consequences

- The project supply chain is continuously audited against security vulnerabilities and licensing liabilities.
- Downstream users and packagers can independently reproduce, verify, and trace release binaries.
