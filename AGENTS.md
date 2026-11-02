# AGENTS.md — Dich engineering contract

This document is the authoritative guide for autonomous coding agents working on Dich. Read `README.md`, `ROADMAP.md`, `docs/architecture.md`, `docs/security.md`, and `docs/adr/0001-scope.md` before modifying code.

## Mission
Build Dich, a production-grade, Rust-based, versioned Linux package store that sources **original signed Debian/Ubuntu APT repositories and `.deb` artifacts** without assuming that arbitrary binary Debian packages are relocatable. It must install and reuse multiple package versions and configurations safely, track dependency/reference graphs, support atomic profiles and safe garbage collection, and ship as a properly documented `.deb` via GitHub Releases.

## Non-negotiable principles
1. Truth over demos: never claim arbitrary `.deb` compatibility, sandboxing, rollback, signatures, or atomicity unless implemented and tested.
2. Do **not** replace, intercept, patch, or invoke system `apt install` or `dpkg -i` for store packages. The system's dpkg database and `/usr` remain untouched.
3. Trust: authenticate `InRelease` or `Release`+`Release.gpg` against configured trusted fingerprints/keyrings; validate index and artifact digests before use. Fail closed. No `trusted=yes`, disabling TLS checks, unauthenticated repositories, or silent fallback.
4. Security: protect against path traversal, symlink and hardlink escapes, archive bombs, special files, dangerous mode bits, post-install scripts, and root-owned arbitrary execution. Never execute `.deb` maintainer scripts by default.
5. Explicit compatibility gate: distinguish `downloaded`, `extracted`, `analyzed`, `relocated`, `activated`, `unsupported`; extraction never implies installability. Reject unsupported ELF, interpreter, absolute-path, service, trigger, and ABI assumptions.
6. No shell interpolation of untrusted input. Use structured process arguments and allowlisted binaries. Dependencies pinned in `Cargo.lock` for application builds.
7. Treat metadata from repositories and artifact paths as untrusted, even when signed. Use bounded streaming, verification and secure filesystem operations.
8. Do not silently modify host loader configuration (`ld.so.conf`), system service files, `/etc`, global environment variables, or host trust anchors.
9. Rust safety: forbid `unsafe` by default; any exception requires an ADR, targeted tests, and review. Use `Result`, typed errors, tracing, and context, never panic on hostile inputs.
10. All durable metadata changes must have crash-consistency semantics and be exercised under failure injection before claiming transactional correctness.

## Agent workflow
- Follow `ROADMAP.md` in order; implement one checkbox-sized milestone at a time. Maintain the roadmap as work is verified; do not auto-mark incomplete checks.
- Before each phase: write acceptance tests (including adversarial cases), document data model and invariants, implement smallest vertical slice, run formatting/lint/tests, and update docs/man/completions.
- Open `docs/decisions.md` for unresolved decisions and add an ADR for consequential choices; never improvise a risky policy silently.
- Do not silently broaden scope to Nix/nixpkgs, mixed-distro installs, automatic interception of APT, arbitrary daemon execution, or all `.deb` support.
- Keep the CLI contract stable; add `--json` with versioned machine-readable errors when functionality is implemented.
- CLI output must clearly distinguish `planned`, `unsupported`, and `completed` actions; nonzero exit for failure.
- Every important bug gets a regression test; security bug gets a negative test.
- Never declare production-ready before the gates in roadmap section `Release criteria` pass.

## Architecture boundaries
- `dich-cli`: interface and diagnostic UX, should contain no package-management business logic.
- `dich-core`: models, store identities, graph semantics, resolver interfaces, transactions, errors.
- `dich-apt`: repository lists, signature/index integrity, metadata parsing, version semantics, source policy.
- `dich-deb`: `.deb` examination/extraction with strict safety limits.
- `dich-elf`: detection and conservative compatibility / relocation reports; do not patch until validated.
- `dich-store`: verified immutable objects, references, profiles, GC, atomic journal.
- Additional crates only when boundaries warrant them. Prefer interfaces and test doubles over hardcoded network/OS access.

## Required commands before merging
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- `cargo doc --workspace --no-deps`
- `cargo audit` once configured (tool availability documented)
- `cargo deny check` once configured
- `cargo run -p dich-cli -- --help`
- `./scripts/check-docs.sh`
- Smoke-test the generated `.deb` in clean Debian and Ubuntu containers/VMs before release.

## Releases
- SemVer, conventional commits, CHANGELOG, signed/tagged release policy documented in `docs/releasing.md`.
- GitHub workflow on `v*` tags builds amd64 Debian artifact, test-install and verify man pages, SHA256 checksums, optional SBOM/provenance, then publishes GitHub Release. Do not claim release signing without a valid signing workflow.
- Add arm64 only with native runner or a proven reproducible cross-compile and container tests.
- Package name `dich`, executable `/usr/bin/dich`, man page `/usr/share/man/man1/dich.1.gz`, completions under standard system directories, config under `/etc/dich/`, runtime state `/var/lib/dich/` only when initialized.
- Release `.deb` installs only Dich itself. Dich's own package is NOT the versioned upstream package store.

## Agent status report format
At the end of each milestone report: implemented files, runnable commands, tests/results, limitations, security risks, and next exact roadmap checkbox. If a required verification could not run, report it plainly; do not invent results.
