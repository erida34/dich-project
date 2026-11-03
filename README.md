# Dich

**Dich** — a version-aware, dependency-sharing package store for Debian and Ubuntu sources, written in Rust.

> **Status: experimental.** The executable can list configured sources, update authenticated repository metadata and query the verified local cache. An experimental, limited metadata planner is available for one source; package installation, a complete Debian resolver, immutable store and ABI relocation are not implemented. Do not use it as a production package manager.

## Vision

Dich will download **original `.deb` files from verified APT repositories**, analyze dependencies and binary compatibility, and place compatible objects into a versioned, shared store. Multiple versions may coexist; profiles select the exact package set; shared dependencies should not be duplicated. Dich does not replace or rewrite the operating system's APT/dpkg database.

### What makes it different
- Upstream is Debian/Ubuntu APT metadata and packages, **not** nixpkgs or a new package format.
- Every store object is uniquely identified and shared wherever compatible.
- Exact dependency resolution and explicit ABI compatibility checks are mandatory.
- System packages and package-maintainer scripts are not executed as host installation actions.
- Compatibility restrictions are surfaced clearly instead of pretending any `.deb` is relocatable.

## Quick start (development)

Prerequisites: supported Rust toolchain with Cargo, Debian/Ubuntu system for integration tests. Linux is the target; initial development may be run on other hosts for model tests only.

```sh
cargo run -p dich-cli -- --help
```

```sh
cargo test --workspace --all-targets
```

```sh
cargo run -p dich-cli -- install openssl@3
```

The last command currently exits with an explicit **not implemented** error. To inspect a trusted source policy without contacting repositories, run `dich --config /absolute/path/sources.toml sources list` (add `--json` for versioned output). Listing means configured, not authenticated or available. For metadata queries, configure real trusted source policy and keyrings as described in `docs/adr/0002-source-policy.md` and `docs/adr/0008-cli-sources.md`. Create a protected local cache directory owned by the invoking user (or root); Dich will not initialize it. Set a suitable maximum metadata age explicitly according to your repository and security requirements, then run:

```sh
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 update
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 search openssl
```

If the repository omits `Valid-Until`, `--allow-missing-valid-until` explicitly permits it while retaining the maximum-age check. Search is a package-name substring; show and versions require an exact name. Results contain name, version, architecture, source and suite only, and do not establish installability. Queries fail when any configured index is unavailable, stale or invalid. An interrupted or failed update can leave a partial cache; rerun update. Protect the cache and clock: deletion or rollback of the entire cache can defeat its per-source rollback floor. An experimental informational plan requires exactly one configured source and an explicit identity boundary:

```sh
dich --config /absolute/path/sources.toml --cache /absolute/path/cache --max-age-seconds 86400 plan hello --distribution ubuntu --suite noble --architecture amd64
```

Plans are labeled `planned` and are not installable or pinned to artifacts. The current resolver supports a narrow relationship subset and rejects, among other cases, most multiarch qualifiers and essential/required packages; it does not infer host packages. The result may therefore be `unsupported` even for ordinary packages such as `hello`. Pre-Depends cycles are conservatively rejected, and the displayed list is not an installation order. It does not check scripts, services or ABI compatibility. Remaining examples below show the *planned* package interface.

## Planned CLI

```text
dich fetch libssl3@3.0
dich inspect ./libssl3.deb
dich install libssl3@3.0 --profile default
dich profile list
dich rollback --profile default
dich store ls
dich store verify
dich gc --dry-run
```

## Repository layout

```text
crates/dich-cli/      CLI binary and command definitions
crates/dich-core/     typed domain models and invariants
crates/dich-apt/      repository trust, metadata and cache libraries (partial)
crates/dich-deb/      safe .deb inspection/extraction (planned)
crates/dich-elf/      ELF and ABI analysis (planned)
crates/dich-store/    durable shared store/profiles/GC (planned)
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
