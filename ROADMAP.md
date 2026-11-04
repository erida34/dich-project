# Dich — implementation roadmap

This checklist is a delivery plan, not a claim that features exist. Each phase requires PR-sized increments, tests and documentation. Never skip security acceptance criteria to make an install command appear to work.

## Phase 0 — foundations (v0.1.0, initial scaffold)
- [x] Repository skeleton, README, agent contract, roadmap, goal, architecture/security/ADRs.
- [x] Rust workspace with documented CLI commands and explicit unimplemented responses.
- [x] Man-page/completion generator and initial packaging/CI workflows (unverified until runners execute).
- [x] Verify `cargo fmt`, `cargo clippy`, `cargo test`, `cargo doc` on a supported Rust toolchain.
- [x] Generate and inspect man pages and shell completions; fix any CLI/documentation drift.
- [x] Add coding guidelines, issue/PR templates, CODEOWNERS as maintainers are identified.

## Phase 1 — repository metadata and trust (v0.2.x)
- [x] Define source config with deb822 `.sources` import, allowed distro suite/component/arch, `Signed-By`, and explicit trust material.
- [x] Read signed `InRelease` or `Release`+`Release.gpg`; verify signature and trusted key binding using audited tooling, no insecure fallback.
- [x] Verify Release checksum of Packages index, support gzip/xz and bounded decompression, reject unsupported formats safely.
- [x] Parse Debian control stanzas, RFC822 continuations, dependency alternatives, epochs and Debian version ordering; unit tests from real fixtures.
- [x] Download `.deb` by trusted index path; verify size and SHA256 and reject redirects/URLs outside configured policy.
- [x] Cache metadata and artifacts atomically with expiry, timestamps, concurrency locks and integrity rechecks.
- [x] `dich sources list`, `dich update`, `dich search`, `dich show`, `dich versions` with output fixtures and offline tests.
- [x] Threat tests: forged Release, wrong key, rollback/freeze, checksum mismatch, truncated indices, decompression bomb, malicious relative URL.

## Phase 2 — dependency resolver (v0.3.x)
- [x] Explicit release/architecture policy. Initially *same distro release and arch only*; no cross-release mixing.
- [x] Model Depends, Pre-Depends, conflicts, provides, alternatives, version constraints, multiarch qualifiers, essential/system base boundaries.
- [x] Deterministic resolver and `dich plan` with explainable decisions, cycles/conflicts/unsat traces (bounded single-source metadata subset; unsupported cases fail closed).
- [x] Pin exact package version, repository snapshot digest, architecture, source identity and artifact SHA256 in lock/plan (informational plan output; no persistent lock replay).
- [x] Reject operations involving unsupported dpkg actions, service managers, kernel modules, unknown package triggers or global state (execution currently denied for all packages; no archive action detection yet).
- [x] Resolver tests for duplicate names/versions, virtual packages, conflicts, downgrades, cyclic dependencies, arch mismatch (downgrade test uses an explicit fixture baseline; profile transitions remain unimplemented).

## Phase 3 — safe artifact handling and immutable store (v0.4.x)
- [x] Read `.deb` ar envelope, control/data tar streams, limits for entries/expanded bytes/files/nesting/path lengths (bounded read-only subset; no extraction).
- [x] Safe extraction that prevents `..`, absolute paths, symlink/hardlink escapes, devices, FIFOs, setuid/setgid, xattrs/capabilities unless explicitly approved (private Linux staging subset; links/extensions rejected).
- [x] Treat package scripts as metadata only; never execute in host root context.
- [x] Adopt canonical store identity hashing verified content plus source/build context and policy version; collision handling and dedup semantics (identity model only; object reuse not implemented).
- [x] Crash-safe staging, fsync, atomic rename, permissions, SQLite metadata (WAL with durability policy), ownership and locking (experimental Linux local-filesystem library subset; process-interruption tests passed, physical power loss unverified).
- [x] Reference graph, store inspect/verify and read-only immutable store convention (experimental Linux library APIs; local-metadata verification and owner-enforced modes, not hard immutability or GC roots).
- [x] `dich fetch`, `dich inspect`, `dich store verify`, `dich store ls` with negative tests for hostile archives and concurrent operations (experimental, Linux-only; live signed Ubuntu fetch verified through explicit HTTP CONNECT proxy; no activation or installability claim).

## Phase 4 — compatibility analyzer and opt-in relocation (v0.5.x)
- [x] Identify ELF objects, interpreter, SONAME, NEEDED, RPATH/RUNPATH, dlopen risks, dynamic loader interactions, symbol versions and libc constraints (bounded byte-level evidence API only; no `.deb` traversal or compatibility approval yet; ADR 0022).
- [x] Scan absolute embedded paths, script shebangs, pkg-config/CMake paths, config files, maintainer triggers, service integration, NSS/locale requirements (bounded heuristic `.deb` evidence, including path-bound ELF reports; no compatibility approval; false negatives and positives remain; ADR 0023).
- [x] Produce machine-readable compatibility report with `supported`, `unsupported`, `review_required` and evidence (schema v1; only the standalone DSO rule below can return `supported`; ADR 0024).
- [x] Initial allowlisted relocatable *library-only* package subset and fixture-based policy; all others fail closed (single self-contained explicit-path DSO, native x86-64 only, fixture/runtime tested; no install or activation; ADR 0025).
- [x] Evaluate alternatives: direct original prefix, patched ELF RUNPATH, wrapper/loader, mount namespaces. ADR before selecting and implementing one (explicit object path selected only for the standalone DSO subset; general relocation rejected; ADR 0026).
- [x] If ELF patching is enabled: preserve signatures/integrity metadata, track transformed output identity, verify ABI and direct/transitive deps, test `dlopen` (not enabled; all current objects remain byte-identical, so no transformed identity exists).
- [x] Cross-runtime fixture smoke: two local single-DSO package versions are reported `supported`, and their unchanged objects load by explicit path on Ubuntu and Debian 13 WSL (no dependency graph, repository trust, installation, or activation claim).
- [x] Fixture integration tests on Ubuntu Noble and Debian 13 WSL for two allowed plugin versions sharing one DSO dependency (separate runtime checks; no mixed-suite, repository-authenticity, install, or activation claim; ADR 0027).

## Phase 5 — profiles, transactions and garbage collection (v0.6.x)
- [x] Explicit profiles backed by atomic relative `current` symlinks and content-derived manifests containing committed store graph references (metadata validated; object bytes are not reverified here; no package files are installed or activated).
- [x] `dich install`, `dich remove`, `dich profile list`, `dich rollback` only for supported subset, with dry-run and confirmation (authenticated single-source standalone DSO and multi-package closure profile install/remove/list, exact dependency edges, profile rollback, and installed-path `dlmopen` runtime checks verified with signed fixtures; ADR 0029).
- [x] Prevent in-place mutation; concurrent transactions, rollback recovery, interruption/failure injection, idempotent replay policy (store objects and generation manifests are read-only 0400 with collision rejection; exclusive database lock serializes concurrent transactions; process-exit fault injection covers all manifest/pointer switch and rollback boundaries with safe restart and idempotent replay).
- [x] Mark-and-sweep GC from profiles, pins and active leases; prevent deletion of active objects; dry-run by default for potentially destructive changes (ADR 0030).
- [x] `dich gc --dry-run`, `dich gc --execute`, diagnostics and human-readable disk usage.
- [x] Real end-to-end smoke tests: install A/B variants, dependency dedup, remove one, GC preserves shared library, rollback.

## Phase 6 — hardening and operational quality (v0.7.x)
- [x] Structured logs with redaction, stable JSON schema and exit codes, helpful errors, progress output (ADR 0031).
- [x] Rootless mode for development; privileged operations mediated by minimal audited boundary (daemon only if justified) (ADR 0032).
- [x] HTTPS/proxy/timeouts/retries, bandwidth and disk limits, cancellation, offline mode, file descriptor/race abuse tests (ADR 0033).
- [x] Security review of key handling, filesystem/TOCTOU attacks, paths, symlinks, privilege model and container limits (ADR 0034).
- [x] Benchmarks for cold/warm metadata sync, package dedup and GC; performance budgets (ADR 0035).
- [x] Integration tests on supported Debian/Ubuntu LTS/current releases; documented support matrix and unsupported targets (ADR 0036).

## Phase 7 — public release (v1.0.0 only after criteria)
- [x] Polish README/getting started, installation and uninstall, config examples, FAQ, man pages, shell completions, CHANGELOG.
- [x] `cargo-deny`, `cargo-audit`, dependency/license policy, reproducible build guidance, SBOM and provenance (ADR 0037).
- [x] GitHub Actions: format, clippy, tests, docs, real `.deb` install/upgrade/remove in clean target images. Hosted run 41717128407 passed both jobs; package smoke passed Debian Bookworm/Trixie and Ubuntu 22.04/24.04.
- [x] Release artifacts for amd64; arm64 only after verified, SHA256SUMS, release notes and verified GitHub Release assets (ADR 0038). Prerelease `v0.7.0` workflow 41723471957 passed and published the amd64 `.deb`, SPDX SBOM, `SHA256SUMS` and provenance. The tag is annotated but unsigned; GPG package signing is not claimed, so this does not satisfy production release readiness.
- [x] Document migration of store DB format, downgrade and recoverability, data durability and backup/restore (ADR 0039).
- [ ] External beta testers, issue triage, threat model review, compatibility limitations explicit (ADR 0040). Internal repository-grounded review is recorded in `dich-project-threat-model.md`, GitHub private vulnerability reporting is enabled, and beta instructions/templates now state the actual single-root DSO scope, disposable-store limits, and absence of response SLAs; external tester results and issue-triage evidence are still missing.

## Release criteria (all required for any production claim)
- [x] Trusted repository verification and fail-closed integrity checks work and are adversarially tested (ADR 0003, ADR 0033).
- [x] Supported package class clearly bounded; incompatible `.deb` refuses install safely (ADR 0025, ADR 0029, ADR 0040).
- [x] Host APT/dpkg/system directories are not mutated by any Dich store operation (ADR 0001, ADR 0034).
- [x] Filesystem extraction resists malicious archives; privileged execution is minimized (ADR 0019, ADR 0034).
- [x] Restart/recovery, profile switch, GC, shared references, and concurrent use covered by integration tests (ADR 0030, ADR 0039).
- [x] Man pages and completions match CLI; `.deb` installs and removes cleanly on declared platforms (ADR 0038, CI deb-smoke). Hosted run 41717128407 verified package install, CLI help, man/completions, reinstall and removal in Debian Bookworm/Trixie and Ubuntu 22.04/24.04.
- [x] CI green, checksums published, changelog/support policy maintained (ADR 0037, ADR 0038). Master CI run 41722390578 and release run 41723471957 passed; release assets include `SHA256SUMS`, and the workflow verified it with `sha256sum -c` before publication.
- [ ] Production release tag and workflow protection: signed tag verified by CI, protected release branch and reviewer gate. Active rulesets protect `master` (ID 26489917: required PR, one approval, latest-push approval, `rust` and `deb-package-smoke` checks, no bypass) and `v*` tags (ID 26488874: repository-owner-only, owner bypass). Release workflow now fails closed and verifies the annotated tag against the configured GPG public-key fingerprint; repository variables `DICH_RELEASE_SIGNING_PUBLIC_KEY` and `DICH_RELEASE_SIGNING_FINGERPRINT` are not configured, and no signed production release exists.
