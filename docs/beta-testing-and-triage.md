# Beta Testing, Issue Triage, Threat Model, and Compatibility Limitations

This document outlines the operational policies for external beta testing, bug triage and compatibility limits. The current internal threat review is in [`../dich-project-threat-model.md`](../dich-project-threat-model.md); no external tester results are claimed.

> **Experimental release:** [v0.7.0](https://github.com/erida34/dich-project/releases/tag/v0.7.0) is an unsigned prerelease. The published `SHA256SUMS` helps detect transfer corruption but is not an independent signature of the release. Test only in a disposable VM or user store. Do not rely on Dich for production workloads or load stored package code from an untrusted publisher.

---

## 1. External Beta Testing Program

Dich is designed for security-conscious Linux environments, reproducible developer tooling, and unprivileged containerized applications requiring versioned packages from signed Debian and Ubuntu repositories.

### 1.1 Target Testing Scenarios
External beta testers should use a disposable Linux amd64/glibc VM or an unprivileged test account and may exercise:
1. **Authenticated repository metadata**: `update`, search and exact-version planning against one explicitly configured signed Debian or Ubuntu source. Record distro, suite and configured signer fingerprint; never disable signature, TLS or freshness checks to make a test pass.
2. **Supported DSO package selection**: On a disposable store, install an exact package only if it passes the documented single-root DSO closure policy in ADRs 0025, 0027 and 0029. The supported result is path selection, not a sandbox or executable package installation. Do not load a selected library unless you trust its publisher; loaded code runs with the caller's privileges.
3. **Fail-closed compatibility reports**: Inspect local fixtures and report whether scripts, services, triggers, non-DSO files, cross-source dependencies or mixed suites are rejected or marked for review. Dich must not execute maintainer scripts.
4. **Profile generations and rollback**: Exercise one requested root package and its dependency closure per profile, on disposable data. Multi-root composition, cross-source resolution and general ELF activation remain unsupported.
5. **Store verification and garbage collection**: Start with `dich gc` dry-run. Use `--execute` only against a disposable store after checking the report; preserve test fixtures and backups.
6. **Concurrency and process interruption**: Use disposable stores only. The project has process-level failure-injection coverage, but that does not prove physical power-loss durability; do not test by abruptly powering off a machine with valuable data.

The release `.deb` install smoke tests cover Debian 12/13 and Ubuntu 22.04/24.04 on amd64. That matrix validates Dich's own package installation, not compatibility of every upstream `.deb` with Dich's store.

### 1.2 Feedback & Bug Reporting Guidelines
Beta testers reporting issues should provide:
- **Environment**: Linux distribution/version (`cat /etc/os-release`), kernel (`uname -r`), architecture (`uname -m`), and filesystem (`stat -f -c %T .`).
- **Exact Dich build and command**: `dich --version`, full command (redact secrets), exit code, and whether `--json` was enabled.
- **Repository/package context**: Debian/Ubuntu distribution, suite, architecture, package and exact version. Include only the minimum source-policy fields needed to reproduce the issue; never attach private keyrings, credentials, tokens or an entire home directory.
- **Reproduction and output**: Minimal steps, expected and actual behavior, relevant stderr/JSON diagnostics, and whether the issue reproduces with a fresh disposable store.
- **Artifact identity when relevant**: Release tag, `.deb` filename and SHA-256. A checksum is an integrity hint, not proof of publisher identity.

---

## 2. Issue Triage Taxonomy

These priorities guide maintainer triage; they are not response-time or resolution guarantees. Reports may take longer to acknowledge or resolve, especially during the experimental beta.

To maintain high software reliability and security posture, reported issues are classified into four severity tiers:

| Priority | Definition | Triage handling |
| :--- | :--- | :--- |
| **P0 - Critical Security** | Trust boundary violation, GPG signature bypass, host filesystem tampering outside store, arbitrary command execution, archive path escape. | Keep details private through GitHub Security Advisories; maintainers assess impact and coordinate disclosure. |
| **P1 - Data Corruption / Hang** | Database corruption (`metadata.sqlite3`), profile generation inconsistency, GC unlinking referenced objects, unrecoverable deadlock. | Preserve evidence and a copy of the disposable test store; prioritize reproduction and data-safety assessment. |
| **P2 - Resolver / Compatibility** | Incorrect result in the supported DSO subset, resolver failure, unexpected parsing error on valid deb822/control metadata. | Confirm the exact supported scope and minimize the reproducer. |
| **P3 - Minor / UX / Docs** | Cosmetic CLI output issue, documentation clarification, non-blocking warning message, shell completion edge case. | Track as a normal improvement. |

### 2.1 Security Vulnerability Handling
Security vulnerabilities must **not** be reported through public GitHub issues. GitHub private vulnerability reporting is enabled; use the repository's **Security → Advisories → Report a vulnerability** flow. No separate maintainer security contact is configured. Adversarial regression tests should accompany confirmed fixes.

---

## 3. Threat Model Review

Dich operates in hostile environments where repositories, packages, network connections, and unprivileged users may be compromised. The following table summarizes the threat vectors, attacker goals, and Dich's architectural defenses:

| Threat Boundary | Attack Vector | Attacker Objective | Dich Defense Mechanism | Verification Test Suite |
| :--- | :--- | :--- | :--- | :--- |
| **Repository Metadata** | Forged `InRelease` or modified `Packages.xz` | Distribute malicious package hashes or metadata | `gpgv` signer allowlist, signed digest chain, fail-closed validation | `crates/dich-apt/src/signature_tests.rs`, `crates/dich-apt/tests/index_verification.rs`, `crates/dich-cli/tests/network_and_resilience.rs` |
| **Network & Transport** | Man-in-the-Middle, hostile redirect, replay | Tamper with downloads or freeze the client on old versions | TLS validation, origin/path redirect policy, rollback floors and Release freshness checks | `crates/dich-apt/src/transport_tests.rs`, `crates/dich-apt/tests/release_freshness.rs`, `crates/dich-cli/tests/network_and_resilience.rs` |
| **Archive Envelope** | Directory traversal, absolute paths, malicious links | Escape private staging or publish an unsafe tree | Bounded parser and descriptor-relative `openat2` staging with beneath/no-symlink constraints | `crates/dich-deb/src/lib.rs` tests, `crates/dich-deb/src/staging.rs`, `crates/dich-cli/tests/security_audit_and_toctou.rs` |
| **Archive Payloads** | Compression bombs, oversized data, hostile ELF | Exhaust local resources or pass misleading compatibility evidence | Byte and file limits, `prlimit` helpers, `statvfs` preflight, conservative ELF reports | `crates/dich-deb/src/lib.rs`, `crates/dich-elf/src/lib.rs`, `crates/dich-cli/tests/network_and_resilience.rs` |
| **Package Lifecycle** | Malicious maintainer scripts or triggers | Execute attacker-controlled setup code | Scripts/triggers are recorded as evidence and never run; unsupported packages fail closed | `crates/dich-deb/src/lib.rs` test `staging_never_executes_control_scripts`; `crates/dich-engine/src` |
| **Store Filesystem** | Hardlinks, symlink races, concurrent mutation | Alter metadata or delete/replace committed objects | Ownership/mode checks, exclusive locks, descriptor-relative traversal and atomic publication | `crates/dich-store/src/lib.rs`, `crates/dich-store/tests/metadata_db.rs`, `crates/dich-cli/tests/security_audit_and_toctou.rs` |
| **Host System State** | Accidental or malicious writes outside Dich state | Conflict with host package manager or compromise services | Dich operations use private cache/store/profile roots; no host APT/dpkg integration or script execution | `crates/dich-cli/tests/security_audit_and_toctou.rs`, `docs/adr/0001-scope.md` |

---

## 4. Explicit Compatibility Limitations

Dich adheres to a strict principle of **truth over demos**. It does **not** claim general Debian package relocatability. Users and beta testers must be fully aware of the following explicit limitations:

### 4.1 What Dich Is NOT
1. **Not a replacement for host `apt` or `dpkg`**: Dich does not install system-wide utilities, manage Linux services, install kernels, configure bootloaders, or update system glibc.
2. **Not an arbitrary binary relocator**: Traditional Linux binaries compiled for Debian/Ubuntu contain hardcoded interpreter paths (`/lib64/ld-linux-x86-64.so.2`), hardcoded data paths (`/usr/share/...`), and hardcoded configuration paths (`/etc/...`). Dich **does not** patch ELF binaries or rewrite RPATHs without an isolated runtime environment (ADR 0026).
3. **Not a systemd or daemon manager**: Services, systemd units, SysV init scripts, udev rules, D-Bus service configs, and cron jobs inside `.deb` packages are ignored and unsupported.

### 4.2 Supported Package Class: x86-64 glibc DSO Closures
Currently, the only package class supported for authenticated profile selection is:
- **x86-64 glibc Dynamic Shared Objects (DSOs)**:
  - Single libraries or closed sets of shared libraries without host integration markers.
  - No maintainer scripts or service files.
  - Acyclic internal dynamic dependencies (`DT_NEEDED`).
  - The CLI selects authenticated object paths in profiles; it does not execute package binaries. `dlmopen` isolates symbol lookup in the test harness only and is not a process sandbox.
  - Packages violating these constraints are conservatively rejected with machine-readable diagnostic errors (`supported: false`, `reason: unsupported_feature`).

### 4.3 Unsupported Scenarios (Fail-Closed)
The following package characteristics result in immediate, fail-closed refusal to install:
- **Maintainer scripts present**: Packages with executable scripts are classified as `unsupported`.
- **System configuration files**: Packages modifying `/etc` or installing daemon configs are rejected.
- **Cross-distribution mixing**: Attempting to combine packages from Ubuntu Noble with Debian Bookworm, or different release suites, fails closed.
- **Unverified repositories**: Unsigned repositories, invalid GPG signatures, or mismatched checksums fail closed.
- **Architecture mismatches**: Foreign architectures (e.g., `arm64`, `i386` on `amd64`) are rejected.
