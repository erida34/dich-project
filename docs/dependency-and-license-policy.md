# Dependency Policy, License Policy, Reproducible Builds, SBOM, and Provenance

## 1. Dependency Admission Policy

Dich maintains a conservative dependency posture. In accordance with project engineering principles:
- **YAGNI & Standard Library First**: Do not add dependencies for functionality that can be cleanly handled by the Rust standard library or platform primitives.
- **Audit & Review**: Every external dependency must be evaluated for security maintenance, vulnerability history, and minimal dependency trees.
- **Pinned Lockfile**: Application builds strictly enforce `--locked` with all dependency checksums recorded in `Cargo.lock`.
- **Automated Security Gates**: CI continuously audits dependencies via `cargo-audit` (RustSec Advisory Database) and enforces compliance via `cargo-deny`.

## 2. License Compliance Policy

Dich is dual-licensed under the **MIT License** and the **Apache License, Version 2.0**.
- All dependencies linked into Dich binaries or libraries must use permissive OSI-approved licenses:
  - `MIT`
  - `Apache-2.0` (and `Apache-2.0 WITH LLVM-exception`)
  - `BSD-2-Clause` / `BSD-3-Clause`
  - `ISC`
  - `Unicode-3.0` / `Unicode-DFS-2016`
  - `Zlib`
- **Prohibited**: Copyleft licenses (GPL, LGPL, AGPL, SSPL) and non-commercial/restrictive licenses are strictly denied by `deny.toml`.
- Continuous compliance is enforced by `cargo-deny check licenses`.

## 3. Reproducible Build Guidance

To ensure independent verification of Dich binary releases:

1. **Deterministic Environment**:
   - Set fixed timestamp for metadata generation:
     ```sh
     export SOURCE_DATE_EPOCH=1730678400
     ```
   - Pin rustc and cargo versions (e.g. Rust 1.85.0+ or current stable pinned in CI).

2. **Path Sanitization**:
   - Strip build-host paths from generated binaries:
     ```sh
     export RUSTFLAGS="--remap-path-prefix $PWD=/build/dich"
     ```

3. **Locked Dependency Resolution**:
   - Always build using `--locked` profile:
     ```sh
     cargo build --release --locked -p dich-cli --bin dich
     ```

4. **Deterministic `.deb` Packaging**:
   - Packaging with `cargo-deb --no-build` packages the pre-built, path-sanitized binary and generated assets without rebuilding.
   - Checksums of produced binaries must match bit-for-bit across independent build directories.

## 4. Software Bill of Materials (SBOM)

Release builds generate a machine-readable Software Bill of Materials in SPDX (2.3) and CycloneDX (1.5) JSON formats:
- Details all direct and transitive Rust dependencies, exact versions, and package hashes from `Cargo.lock`.
- Produced during the release workflow and published alongside release `.deb` packages and checksum files (`SHA256SUMS`).

## 5. Build Provenance and Attestations

Official GitHub Releases publish cryptographically signed build provenance attestations:
- Generated using GitHub's artifact attestation service (`actions/attest-build-provenance`).
- Verifies that the `.deb` release artifacts were built from the immutable commit tag on the official repository runners.
- Verification command:
  ```sh
  gh attestation verify dich_0.1.0-1_amd64.deb --owner dich-project
  ```
