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
- [ ] Verify Release checksum of Packages index, support gzip/xz and bounded decompression, reject unsupported formats safely.
- [ ] Parse Debian control stanzas, RFC822 continuations, dependency alternatives, epochs and Debian version ordering; unit tests from real fixtures.
- [ ] Download `.deb` by trusted index path; verify size and SHA256 and reject redirects/URLs outside configured policy.
- [ ] Cache metadata and artifacts atomically with expiry, timestamps, concurrency locks and integrity rechecks.
- [ ] `dich sources list`, `dich update`, `dich search`, `dich show`, `dich versions` with output fixtures and offline tests.
- [ ] Threat tests: forged Release, wrong key, rollback/freeze, checksum mismatch, truncated indices, decompression bomb, malicious relative URL.

## Phase 2 — dependency resolver (v0.3.x)
- [ ] Explicit release/architecture policy. Initially *same distro release and arch only*; no cross-release mixing.
- [ ] Model Depends, Pre-Depends, conflicts, provides, alternatives, version constraints, multiarch qualifiers, essential/system base boundaries.
- [ ] Deterministic resolver and `dich plan` with explainable decisions, cycles/conflicts/unsat traces.
- [ ] Pin exact package version, repository snapshot digest, architecture, source identity and artifact SHA256 in lock/plan.
- [ ] Reject operations involving unsupported dpkg actions, service managers, kernel modules, unknown package triggers or global state.
- [ ] Resolver tests for duplicate names/versions, virtual packages, conflicts, downgrades, cyclic dependencies, arch mismatch.

## Phase 3 — safe artifact handling and immutable store (v0.4.x)
- [ ] Read `.deb` ar envelope, control/data tar streams, limits for entries/expanded bytes/files/nesting/path lengths.
- [ ] Safe extraction that prevents `..`, absolute paths, symlink/hardlink escapes, devices, FIFOs, setuid/setgid, xattrs/capabilities unless explicitly approved.
- [ ] Treat package scripts as metadata only; never execute in host root context.
- [ ] Adopt canonical store identity hashing verified content plus source/build context and policy version; collision handling and dedup semantics.
- [ ] Crash-safe staging, fsync, atomic rename, permissions, SQLite metadata (WAL with durability policy), ownership and locking.
- [ ] Reference graph, store inspect/verify and read-only immutable store convention; distinguish best-effort immutability from hard enforcement.
- [ ] `dich fetch`, `dich inspect`, `dich store verify`, `dich store ls` with negative tests for hostile archives and concurrent operations.

## Phase 4 — compatibility analyzer and opt-in relocation (v0.5.x)
- [ ] Identify ELF objects, interpreter, SONAME, NEEDED, RPATH/RUNPATH, dlopen risks, dynamic loader interactions, symbol versions and libc constraints.
- [ ] Scan absolute embedded paths, script shebangs, pkg-config/CMake paths, config files, maintainer triggers, service integration, NSS/locale requirements.
- [ ] Produce machine-readable compatibility report with `supported`, `unsupported`, `review_required` and evidence.
- [ ] Initial allowlisted relocatable *library-only* package subset and fixture-based policy; all others fail closed.
- [ ] Evaluate alternatives: direct original prefix, patched ELF RUNPATH, wrapper/loader, mount namespaces. ADR before selecting and implementing one.
- [ ] If ELF patching is enabled: preserve signatures/integrity metadata, track transformed output identity, verify ABI and direct/transitive deps, test `dlopen`.
- [ ] Integration tests on Debian/Ubuntu VM/container for at least two allowed versions with shared dependency (not mixed suites).

## Phase 5 — profiles, transactions and garbage collection (v0.6.x)
- [ ] Explicit profiles backed by atomic generation symlinks and manifest including immutable store references.
- [ ] `dich install`, `dich remove`, `dich profile list`, `dich rollback` only for supported subset, with dry-run and confirmation.
- [ ] Prevent in-place mutation; concurrent transactions, rollback recovery, interruption/failure injection, idempotent replay policy.
- [ ] Mark-and-sweep GC from profiles, pins and active leases; prevent deletion of active objects; dry-run by default for potentially destructive changes.
- [ ] `dich gc --dry-run`, `dich gc --execute`, diagnostics and human-readable disk usage.
- [ ] Real end-to-end smoke tests: install A/B variants, dependency dedup, remove one, GC preserves shared library, rollback.

## Phase 6 — hardening and operational quality (v0.7.x)
- [ ] Structured logs with redaction, stable JSON schema and exit codes, helpful errors, progress output.
- [ ] Rootless mode for development; privileged operations mediated by minimal audited boundary (daemon only if justified).
- [ ] HTTPS/proxy/timeouts/retries, bandwidth and disk limits, cancellation, offline mode, file descriptor/race abuse tests.
- [ ] Security review of key handling, filesystem/TOCTOU attacks, paths, symlinks, privilege model and container limits.
- [ ] Benchmarks for cold/warm metadata sync, package dedup and GC; performance budgets.
- [ ] Integration tests on supported Debian/Ubuntu LTS/current releases; documented support matrix and unsupported targets.

## Phase 7 — public release (v1.0.0 only after criteria)
- [ ] Polish README/getting started, installation and uninstall, config examples, FAQ, man pages, shell completions, CHANGELOG.
- [ ] `cargo-deny`, `cargo-audit`, dependency/license policy, reproducible build guidance, SBOM and provenance.
- [ ] GitHub Actions: format, clippy, tests, docs, real `.deb` install/upgrade/remove in clean target images.
- [ ] Release artifacts for amd64; arm64 only after verified, SHA256SUMS, release notes and verified GitHub Release assets.
- [ ] Document migration of store DB format, downgrade and recoverability, data durability and backup/restore.
- [ ] External beta testers, issue triage, threat model review, compatibility limitations explicit.

## Release criteria (all required for any production claim)
- Trusted repository verification and fail-closed integrity checks work and are adversarially tested.
- Supported package class clearly bounded; incompatible `.deb` refuses install safely.
- Host APT/dpkg/system directories are not mutated by any Dich store operation.
- Filesystem extraction resists malicious archives; privileged execution is minimized.
- Restart/recovery, profile switch, GC, shared references, and concurrent use covered by integration tests.
- Man pages and completions match CLI; `.deb` installs and removes cleanly on declared platforms.
- CI green, checksums published, changelog/support policy maintained.
