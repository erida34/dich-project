# Release engineering

## Policy
Use SemVer tags `vX.Y.Z`, update the matching changelog section, validate the exact release commit, build a Debian binary package, test archive contents and install/remove behavior on declared base OS images, then publish checksums and GitHub release assets. Production tags must be annotated and signed (`git tag -s`), with the trusted signer verified by the release workflow. GitHub ruleset `Protect version tags` (ID 26488874) restricts `v*` tag creation/update/deletion to the repository owner, who can bypass it; the default branch currently has no protection rule or reviewer-gated release environment. The `v0.7.0` experimental prerelease tag is unsigned, so it does not satisfy production release policy. Build provenance is not a signature of package contents or a review of source safety. Before v1, version numbers convey interface stage, not production suitability.

## Local build
1. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`.
2. Generate assets: `cargo run -p dich-cli --bin dich-gen-docs -- packaging/generated`.
3. Install the pinned `cargo-deb` 3.8.0 with `cargo install cargo-deb --version 3.8.0 --locked`, then run `cargo deb -p dich-cli`.
4. Inspect archive: `dpkg-deb --contents target/debian/*.deb`, `dpkg-deb --info ...`.
5. Test installation of Dich itself (not package manager semantics) inside throwaway Debian/Ubuntu containers and verify `man dich`, shell completion file locations and uninstallation.

## GitHub Actions
`ci.yml` runs Rust checks, dependency/license audits and a four-distribution `.deb` smoke matrix. Package builds run on Ubuntu 22.04 to keep the executable's glibc requirement at or below the declared 2.35 baseline; the hosted package build produced `libc6 >= 2.34`. Hosted CI runs 41721280122 and 41722390578 passed Rust checks and the package install/reinstall/remove matrix on Debian 12 Bookworm, Debian 13 Trixie, Ubuntu 22.04 Jammy and Ubuntu 24.04 Noble. Release run 41723471957 for tag `v0.7.0` passed the same Rust/audit gates, built the amd64 `.deb`, tested it on all four images, generated SPDX 2.3 dependency data, verified `SHA256SUMS`, created build provenance and published a GitHub prerelease. Assets are `dich_0.7.0-1_amd64.deb`, `dich.spdx.json`, and `SHA256SUMS`. The first tag run 41722034108 failed before job setup because the provenance action SHA did not resolve; the exact upstream v2.2.3 commit is now pinned. The published tag is annotated but unsigned; production release policy still requires signed tags/protected tag rules. GitHub build provenance is configured; GPG artifact signing is not claimed.

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
   `.github/workflows/release.yml` builds the release package and executes containerized smoke tests in pinned Debian and Ubuntu base images, verifying installation, manual page indexing, Russian CLI output, vendor completions, reinstall and clean removal. The `v0.7.0` run 41723471957 and `v0.7.3` run 41783499470 passed this matrix; `v0.7.3` is published as an experimental prerelease. Runs for `v0.7.1` and `v0.7.2` caught and fixed Debian's dpkg path filters for localized man pages.

   Latest experimental prerelease: [`v0.7.9`](https://github.com/erida34/dich-project/releases/tag/v0.7.9). Release run [41829280633](https://github.com/erida34/dich-project/actions/runs/41829280633) passed formatting, clippy, workspace tests, cargo-deny/audit, package build, SPDX generation, and install/reinstall/remove smoke tests on all four supported amd64 images. The package smoke also ran authenticated `dich update` in both Debian images to exercise the generated multi-signature trust policy. Release assets are `dich_0.7.9-1_amd64.deb` (SHA-256 `d9b16fdab3c9c05c68d5d42be56caf093dd480670bfb2eea9cd3ec7950c50c23`), `dich.spdx.json` (SHA-256 `db1823729322e4e2d53f42835c6805ca71062790bfddaf62190469e1890e3c8f`), and `SHA256SUMS` (SHA-256 `6f58c7ca4c456f1813bc131d5bf3995dab5fb116a34053499174858cc27d3038`). The release is an experimental prerelease; its annotated tag is unsigned and GPG artifact signing is not claimed, so production release gates remain open.


## Opt-in live fetch check

On a network-capable Linux test target, set `DICH_LIVE_CONFIG` to an explicit trusted single-source policy, `DICH_LIVE_CACHE` to a new private directory, and `DICH_LIVE_PACKAGE`, `DICH_LIVE_VERSION`, `DICH_LIVE_COMPONENT` to an exact indexed artifact. The CLI freshness default is 24 hours. Populate the dedicated cache with `dich --config "$DICH_LIVE_CONFIG" --cache "$DICH_LIVE_CACHE" update`; pass `--max-age-seconds "$DICH_LIVE_MAX_AGE"` before `update` only when testing an override. A repository without `Valid-Until` remains bounded by the 24-hour signed `Date`; add `--require-valid-until` to opt into rejecting that metadata. Then run:

```sh
cargo test -p dich-cli --test fetch_cli live_exact_fetch_downloads_signed_artifact -- --ignored --exact
```

The test requires `downloaded`, not `cached`, and leaves the verified blob in the dedicated cache. It does not install or activate it.

For an offline authenticated-cache check, provide a dedicated `DICH_REAL_CACHE`, trusted single-source `DICH_REAL_CONFIG`, original signed `DICH_REAL_RELEASE`, xz `DICH_REAL_INDEX`, `DICH_REAL_ARTIFACT`, exact `DICH_REAL_PACKAGE`, `DICH_REAL_VERSION`, `DICH_REAL_COMPONENT` and explicit `DICH_REAL_MAX_AGE`. Set `DICH_REAL_ALLOW_MISSING_VALID_UNTIL=1` only when intentionally testing such a repository. Run `cargo test -p dich-cli --test fetch_cli real_signed_cached_artifact_fetch -- --ignored --exact`. This tests a revalidated cache hit, not network downloading.
