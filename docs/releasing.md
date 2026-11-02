# Release engineering

## Policy
Use semver tags `vX.Y.Z`, update changelog, validate the exact release commit, build a Debian binary package, test archive contents and install/remove behavior on declared base OS images, then publish checksums and GitHub release assets. Before v1, version numbers convey interface stage, not production suitability.

## Local build
1. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`.
2. Generate assets: `cargo run -p dich-cli --bin dich-gen-docs -- packaging/generated`.
3. Install `cargo-deb` and run `cargo deb -p dich-cli`.
4. Inspect archive: `dpkg-deb --contents target/debian/*.deb`, `dpkg-deb --info ...`.
5. Test installation of Dich itself (not package manager semantics) inside throwaway Debian/Ubuntu containers and verify `man dich`, shell completion file locations and uninstallation.

## GitHub Actions
`ci.yml` runs Rust checks and docs; `release.yml` builds amd64 `.deb` on a Linux runner, smoke-tests in a Debian container, publishes artifact + SHA256SUMS. Actions are written with release tags from widely used publishers but must be pinned to immutable commit SHAs before production; ensure repository permissions and release protection rules are configured. Publishing artifacts is deliberately limited to `v*` tags. No GPG signing/attestation is asserted by the scaffold.

## Required before v1
Versioned state migration, supported distro matrix, signed provenance strategy, SBOM, dependency audits, reproducibility investigation, real install/rollback/GC tests and private vulnerability disclosure process.
