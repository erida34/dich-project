# Release engineering

## Policy
Use SemVer tags `vX.Y.Z`, update the matching changelog section, validate the exact release commit, build a Debian binary package, test archive contents and install/remove behavior on declared base OS images, then publish checksums and GitHub release assets. Release tags should be annotated and signed (`git tag -s`) and verified by a maintainer before push. The current tag workflow does not independently verify OpenPGP tag signatures; protect `v*` tags and require maintainer review in GitHub before relying on the workflow for production releases. Build provenance is not a signature of the package contents or a review of source safety. Before v1, version numbers convey interface stage, not production suitability.

## Local build
1. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`.
2. Generate assets: `cargo run -p dich-cli --bin dich-gen-docs -- packaging/generated`.
3. Install the pinned `cargo-deb` 3.8.0 with `cargo install cargo-deb --version 3.8.0 --locked`, then run `cargo deb -p dich-cli`.
4. Inspect archive: `dpkg-deb --contents target/debian/*.deb`, `dpkg-deb --info ...`.
5. Test installation of Dich itself (not package manager semantics) inside throwaway Debian/Ubuntu containers and verify `man dich`, shell completion file locations and uninstallation.

## GitHub Actions
`ci.yml` runs Rust checks, dependency/license audits and a four-distribution `.deb` smoke matrix. Package builds run on Ubuntu 22.04 to keep the executable's glibc requirement at or below the declared 2.35 baseline; the hosted package build produced `libc6 >= 2.34`. Hosted CI runs 41721280122 and 41722390578 passed Rust checks and the package install/reinstall/remove matrix on Debian 12 Bookworm, Debian 13 Trixie, Ubuntu 22.04 Jammy and Ubuntu 24.04 Noble. `release.yml` rejects a tag whose SemVer does not match the package version, repeats the locked code/audit gates, builds amd64 `.deb`, and smoke-tests the same pinned images. It generates SPDX 2.3 dependency data with pinned `cargo-sbom` 0.10.0, includes the scoped webpki root-data license, and hashes the `.deb` plus SBOM in `SHA256SUMS`. Actions and release-image manifests are pinned to immutable commits/digests; `cargo-deb` is pinned to 3.8.0. First tag run 41722034108 failed before job setup because the provenance action SHA did not resolve; the ref is corrected and master CI is green, but the tag workflow must be rerun before claiming release assets. GitHub build provenance is configured; GPG artifact signing is not claimed.

## Release Artifacts and Architecture Policy

1. **Architecture Scope**:
   - `amd64` (x86_64) is the primary verified target.
   - `arm64` is deferred until native runner verification and container smoke testing are integrated; no unverified cross-compiled binaries are published (ADR 0038).

2. **Published Assets on GitHub Releases**:
   - `dich_<upstream-version>-<debian-revision>_amd64.deb`: Debian package (for example, `dich_0.7.0-1_amd64.deb`).
   - `SHA256SUMS`: SHA-256 digests of all released files.
- `dich.spdx.json`: Machine-readable SPDX 2.3 SBOM generated from the locked `dich-cli` dependency graph.
   - Cryptographic build provenance attestations generated via `actions/attest-build-provenance`.

3. **Release Gate Verification**:
   Before release publication, `.github/workflows/release.yml` builds the release package and executes containerized smoke tests in pinned Debian and Ubuntu base images, verifying installation, manual page indexing, vendor completions, reinstall and clean removal. Hosted CI run 41717128407 passed this smoke matrix for the current pre-version-bump commit. The release-tag workflow itself has not run and no GitHub Release assets are published.


## Opt-in live fetch check

On a network-capable Linux test target, set `DICH_LIVE_CONFIG` to an explicit trusted single-source policy, `DICH_LIVE_CACHE` to a new private directory, `DICH_LIVE_MAX_AGE` to the chosen maximum Release age in seconds, and `DICH_LIVE_PACKAGE`, `DICH_LIVE_VERSION`, `DICH_LIVE_COMPONENT` to an exact indexed artifact. Populate the dedicated cache with `dich --config "$DICH_LIVE_CONFIG" --cache "$DICH_LIVE_CACHE" --max-age-seconds "$DICH_LIVE_MAX_AGE" update`. If the repository lacks Valid-Until, add `--allow-missing-valid-until` to update and explicitly set `DICH_LIVE_ALLOW_MISSING_VALID_UNTIL=1` for the test. Then run:

```sh
cargo test -p dich-cli --test fetch_cli live_exact_fetch_downloads_signed_artifact -- --ignored --exact
```

The test requires `downloaded`, not `cached`, and leaves the verified blob in the dedicated cache. It does not install or activate it.

For an offline authenticated-cache check, provide a dedicated `DICH_REAL_CACHE`, trusted single-source `DICH_REAL_CONFIG`, original signed `DICH_REAL_RELEASE`, xz `DICH_REAL_INDEX`, `DICH_REAL_ARTIFACT`, exact `DICH_REAL_PACKAGE`, `DICH_REAL_VERSION`, `DICH_REAL_COMPONENT` and explicit `DICH_REAL_MAX_AGE`. Set `DICH_REAL_ALLOW_MISSING_VALID_UNTIL=1` only when intentionally testing such a repository. Run `cargo test -p dich-cli --test fetch_cli real_signed_cached_artifact_fetch -- --ignored --exact`. This tests a revalidated cache hit, not network downloading.
