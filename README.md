# Dich

**Dich** — a version-aware, dependency-sharing package store for Debian and Ubuntu sources, written in Rust.

> **Status: experimental.** Dich verifies configured APT signing keys and metadata, downloads exact artifacts, and supports a tightly bounded profile install for authenticated x86-64 glibc DSO closures. The install command stores unchanged objects and selects profile metadata; callers must load the returned paths explicitly, and Dich does not execute package code. General Debian package installation, a complete resolver, hard immutable storage, arbitrary ABI compatibility, GC and production recovery are not implemented. Do not use it as a production package manager.

## Vision

Dich will download **original `.deb` files from verified APT repositories**, analyze dependencies and binary compatibility, and place compatible objects into a versioned, shared store. Multiple versions may coexist; profiles select the exact package set; shared dependencies should not be duplicated. Dich does not replace or rewrite the operating system's APT/dpkg database.

### What makes it different
- Upstream is Debian/Ubuntu APT metadata and packages, **not** nixpkgs or a new package format.
- Every store object is uniquely identified and shared wherever compatible.
- Exact dependency resolution and explicit ABI compatibility checks are mandatory.
- System packages and package-maintainer scripts are not executed as host installation actions.
- Compatibility restrictions are surfaced clearly instead of pretending any `.deb` is relocatable.

## Quick start (development)

Prerequisites: supported Rust toolchain with Cargo, Debian/Ubuntu system for integration tests, and `gpg`, `gpgv`, `prlimit`, `gzip`, `xz`, `zstd` and `cc` for the relevant fixture tests. Linux is the target; initial development may be run on other hosts for model tests only.

```sh
cargo run -p dich-cli -- --help
```

```sh
cargo test --workspace --all-targets
```

```sh
cargo run -p dich-cli -- --help
```

To inspect a trusted source policy without contacting repositories, run `dich --config /absolute/path/sources.toml sources list` (add `--json` for versioned output). Listing means configured, not authenticated or available. For metadata queries and installation, configure real trusted source policy and keyrings as described in `docs/adr/0002-source-policy.md` and `docs/adr/0008-cli-sources.md`. Create a protected local cache directory owned by the invoking user (or root); Dich will not initialize it. Set a suitable maximum metadata age explicitly according to your repository and security requirements, then run:

```sh
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 update
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 search openssl
```

If the repository omits `Valid-Until`, `--allow-missing-valid-until` explicitly permits it while retaining the maximum-age check. Search is a package-name substring; show and versions require an exact name. Results contain name, version, architecture, source and suite only, and do not establish installability. Queries fail when any configured index is unavailable, stale or invalid. An interrupted or failed update can leave a partial cache; rerun update. Protect the cache and clock: deletion or rollback of the entire cache can defeat its per-source rollback floor. An experimental informational plan requires exactly one configured source and an explicit identity boundary:

```sh
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 plan hello --distribution ubuntu --suite noble --architecture amd64
```

To download one exact artifact from an already updated, authenticated cache with exactly one configured source, select its component and version explicitly. Where direct connections are unavailable, network commands accept an explicit unauthenticated HTTP CONNECT proxy; proxy environment variables are ignored:

```sh
dich --https-proxy http://proxy.example:8080 --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 update
dich --https-proxy http://proxy.example:8080 --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 fetch package --exact-version 1.2-3 --component main
```

The HTTPS origin certificate and signed repository metadata remain verified. An intercepting proxy with an untrusted certificate is rejected. Proxy credentials and environment-based proxy discovery are unsupported (ADR 0021).

```sh
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 fetch hello --exact-version 1.0-1 --component main
```

The example version is illustrative; select a version actually present in the authenticated index. Fetch rechecks signatures and digests and reuses a valid cached artifact when available. The output distinguishes `cached` from `downloaded`; a corrupt cache entry fails closed. To additionally publish a conservative extracted tree, provide an existing protected `--store-dir` and add `--publish-tree`. This may initialize metadata within that directory and rejects unsupported archives. It never activates the package or establishes installability; a failure may leave the verified artifact cached. A live Ubuntu Noble metadata update and exact package fetch were verified in WSL through an explicit credential-free HTTP CONNECT proxy; historical snapshot freshness overrides used for this check are not deployment guidance.

Local compatibility inspection does not authenticate a package. To inspect a DSO and explicitly supplied dependency package together, use `dich --json inspect ./plugin.deb --with ./common.deb`. The narrow x86-64 glibc closure rule requires every ELF dependency and imported symbol to resolve within the supplied set and reports a dependency-first SONAME load order. Local inputs remain unverified and non-installable. The isolated `dlmopen` fixture is a symbol namespace boundary, not a sandbox; loaded code can run with the caller's privileges. See ADR 0027.

Plans are labeled `planned` and include signed-snapshot and artifact SHA256 identities in JSON, but cannot yet be replayed as locks. The resolver supports a narrow relationship subset and rejects, among other cases, most multiarch qualifiers and essential/required packages; it does not infer host packages. `install` rechecks fresh signed metadata and only accepts the authenticated DSO class after the complete selected closure passes ADR 0027. Without `--yes`, it only plans; with confirmation, it stores unchanged trees and selects one requested root per profile. It reports explicit object paths and load order for callers; Dich does not load them, provide a sandbox or change loader configuration. Use separate profiles for separate requested roots. `remove` also requires `--yes` to deactivate the profile pointer; objects are retained, and GC is not implemented. An existing store can be inspected with `dich --store-dir /absolute/path/store store ls` and verified with `dich --store-dir /absolute/path/store store verify OBJECT_ID --kind tree`. Listing reads metadata without checking contents; verification checks local bytes without refreshing repository signatures or proving compatibility. Local `dich inspect` inputs remain unverified even when the report says `supported`. See ADRs 0025–0029.

## Experimental profile commands

```text
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --store-dir /absolute/path/store --max-age-seconds 86400 install libexample --profile app --exact-version 1.2-3
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --store-dir /absolute/path/store --max-age-seconds 86400 install libexample --profile app --exact-version 1.2-3 --yes
dich profile list
dich remove libexample --profile app --yes
dich rollback --profile default
dich gc --dry-run
```

The first `install` invocation prints a metadata-only plan; `--exact-version` constrains the requested root to that Debian version. Only the confirmed invocation fetches, checks compatibility, publishes and selects the DSO closure. A later exact-version install in the same profile creates a new generation; `rollback --profile app --yes` switches to the retained prior generation. These profile operations only select metadata and do not load or activate libraries. `gc` remains unsupported.

## Repository layout

```text
crates/dich-cli/      CLI binary and command definitions
crates/dich-engine/   authenticated install orchestration
crates/dich-core/     typed domain models and invariants
crates/dich-apt/      repository trust, metadata and cache libraries (partial)
crates/dich-deb/      bounded .deb inspection and private staging (partial)
crates/dich-elf/      ELF and ABI analysis (planned)
crates/dich-store/    experimental objects, graphs and metadata profiles; GC planned
docs/                architecture, threat model, ADRs and policies
packaging/           distro packaging helpers and examples
scripts/             documentation verification
.github/workflows/    quality and GitHub Releases
```

## Design constraints

- Signed Release metadata, hash-verified indices and blobs, fail-closed errors.
- No cross-release mixing by default (e.g. Debian stable + testing or Ubuntu releases).
- No `/usr`, `/etc`, `/var/lib/dpkg` mutation by Dich-managed store operations.
- Maintain a whitelist of compatible package classes before enabling real installation.
- `glibc`, dynamic loader and library symbol-version constraints must be validated.

## Build and packaging

The GitHub tag workflow is a scaffold for Linux amd64 `.deb` builds. It generates man pages and shell completions from the same Clap command definition and packages them together with the executable. CI checks package content and install/remove smoke tests. Tag builds are not proof of a production-ready package manager. See `docs/releasing.md`.

Build a local Debian package (after installing cargo-deb):

```sh
cargo run -p dich-cli --bin dich-gen-docs -- packaging/generated
```

```sh
cargo deb -p dich-cli
```

For current supported command syntax and component responsibilities, see `docs/architecture.md` and `man dich` after installation.

## Security

**This tool processes untrusted repository data and archives**. Do not enable installation until signed metadata validation, safe extraction, store transaction guarantees, and compatibility gates pass the tests in `ROADMAP.md`. Report vulnerabilities privately via `SECURITY.md`.

## Project

- License: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
- Maintainers: to be appointed; do not invent GitHub URLs or release signing keys.
- Contributions: see `CONTRIBUTING.md`.
- Roadmap: `ROADMAP.md`.
