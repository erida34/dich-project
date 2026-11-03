# Dich

**Dich** — a version-aware, dependency-sharing package store for Debian and Ubuntu sources, written in Rust.

> **Status: experimental.** The executable can list explicitly configured sources; other package operations remain unsupported. Library components verify signatures and artifacts, but the CLI has no repository update pipeline, package installation, immutable store or ABI relocation. Do not use it as a production package manager.

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

The last command currently exits with an explicit **not implemented** error. To inspect a trusted source policy without contacting repositories, run `dich --config /absolute/path/sources.toml sources list` (add `--json` for versioned output). Listing means configured, not authenticated or available. Other CLI examples below show the *planned* interface.

## Planned CLI

```text
dich update
dich search openssl
dich versions libssl3
dich show libssl3
dich plan libssl3@3.0
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
