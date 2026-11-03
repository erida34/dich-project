# Beta Testing, Issue Triage, Threat Model, and Compatibility Limitations

This document outlines the operational policies for external beta testing, bug triage, threat model analysis, and explicit runtime compatibility limitations for Dich.

---

## 1. External Beta Testing Program

Dich is designed for security-conscious Linux environments, reproducible developer tooling, and unprivileged containerized applications requiring versioned packages from signed Debian and Ubuntu repositories.

### 1.1 Target Testing Scenarios
External beta testers are encouraged to exercise Dich against the following scenarios:
1. **Rootless User Store Operations**: Running `dich` entirely under unprivileged user accounts with store directories in `~/.local/share/dich` or custom paths, without `sudo` or host `apt` interaction.
2. **Profile Generation & Atomic Rollback**: Creating multiple generations of application profiles, installing shared library closures, switching between versions, rolling back, and verifying runtime behavior via `dlmopen` or dynamic loaders.
3. **Multi-Source Configuration & Suite Snapshots**: Configuring multiple repository mirrors, testing snapshot pinning, and verifying fail-closed behavior against expired repositories or key rotations.
4. **Garbage Collection Safety**: Exercising mark-and-sweep GC under active profiles, testing disk space reclamation, and validating that referenced shared objects are never deleted.
5. **Concurrent Operations & Crash Resilience**: Executing concurrent `dich` invocations against a single store, testing lock contention handling, and verifying database integrity after simulated abrupt process termination.

### 1.2 Feedback & Bug Reporting Guidelines
Beta testers reporting issues must provide:
- **Environment Context**: Linux distribution and version (`cat /etc/os-release`), kernel version (`uname -r`), CPU architecture (`uname -m`), and filesystem type (`stat -f -c %T .`).
- **Exact Dich Version & Command**: `dich --version`, the full command line executed, and whether `--json` was supplied.
- **Reproducible Test Case**: A minimal repository policy (`sources.toml` or `sources.list.d/*.sources`), target package names, and full stderr output.
- **Diagnostics Output**: Any error codes and diagnostic hints reported in structured JSON format.

---

## 2. Issue Triage Taxonomy and SLAs

To maintain high software reliability and security posture, reported issues are classified into four severity tiers:

| Severity | Definition | Response Target | Resolution Target |
| :--- | :--- | :--- | :--- |
| **P0 - Critical Security** | Trust boundary violation, GPG signature bypass, host filesystem tampering outside store, arbitrary command execution, archive path escape. | < 12 hours | < 48 hours via security patch release |
| **P1 - Data Corruption / Hang** | Database corruption (`metadata.sqlite3`), profile generation inconsistency, GC unlinking referenced objects, unrecoverable deadlock. | < 24 hours | Next minor/patch release |
| **P2 - Resolver / Compatibility** | False positive rejection in the supported DSO subset, resolver backtracking failure, unexpected parsing error on valid deb822/control metadata. | < 3 days | Planned sprint cycle |
| **P3 - Minor / UX / Docs** | Cosmetic CLI output issue, documentation clarification, non-blocking warning message, shell completion edge case. | < 7 days | Standard backlog |

### 2.1 Security Vulnerability Handling
Security vulnerabilities must **not** be reported through public GitHub issues. Responsible disclosure follows the process defined in `SECURITY.md`:
- Send encrypted reports to the maintainer contact with reproduction artifacts.
- CVE identifiers are requested upon confirmation of reproducible vulnerabilities.
- Adversarial regression tests are committed alongside fixes to prevent regression.

---

## 3. Threat Model Review

Dich operates in hostile environments where repositories, packages, network connections, and unprivileged users may be compromised. The following table summarizes the threat vectors, attacker goals, and Dich's architectural defenses:

| Threat Boundary | Attack Vector | Attacker Objective | Dich Defense Mechanism | Verification Test Suite |
| :--- | :--- | :--- | :--- | :--- |
| **Repository Metadata** | Forged `InRelease` or modified `Packages.xz` | Distribute malicious package hashes or metadata | Strict `gpgv` signature verification against operator keyrings, digest chaining (`Release` -> `Packages` -> `.deb`), fail-closed validation | `crates/dich-apt/tests/repository_signatures.rs`, `crates/dich-cli/tests/network_and_resilience.rs` |
| **Network & Transport** | Man-in-the-Middle (MitM), rogue proxy, replay attacks | Tamper with downloads, freeze client on old versions | TLS enforced via `rustls`, anti-rollback floor checks, Valid-Until/Date expiration checks, strict URL/proxy sanitization | `crates/dich-apt/tests/artifact_fetch.rs`, `crates/dich-cli/tests/network_and_resilience.rs` |
| **Archive Envelope** | Directory traversal (`../../etc/shadow`), absolute paths (`/bin/sh`), symlink traps | Escape destination directory, overwrite host system files | Confined staging with Linux `openat2` (`RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS`), strict archive parser path rejection | `crates/dich-deb/tests/staging.rs`, `crates/dich-cli/tests/security_audit_and_toctou.rs` |
| **Archive Payloads** | Archive bombs (compression ratio abuse), infinite streams | Exhaust host memory or disk space | Strict file size and decompressed byte limits, `RateLimitedReader`, `prlimit` CPU/memory caps, free disk checks via `statvfs` | `crates/dich-deb/tests/archive_bombs.rs`, `crates/dich-cli/tests/network_and_resilience.rs` |
| **Package Lifecycle** | Malicious maintainer scripts (`preinst`, `postinst`, `prerm`, `postrm`) | Arbitrary code execution during package setup | Maintainer scripts are **never executed**. Control files are parsed as read-only diagnostic metadata only | `crates/dich-deb/tests/scripts.rs`, `crates/dich-engine/tests/` |
| **Store Filesystem** | Hardlink attacks, symlink races, TOCTOU swaps | Hijack store database (`metadata.sqlite3`) or mutate committed trees | Strict ownership/mode checks (0700/0600), immutable object files (0400), exclusive `flock` on `metadata.lock`, atomic rename without replace | `crates/dich-store/tests/store_metadata.rs`, `crates/dich-cli/tests/security_audit_and_toctou.rs` |
| **Host System State** | Tampering with `/etc`, `/usr`, `/var/lib/dpkg` | Conflict with host package manager or compromise host services | System directories are **never touched**. Dich operates in isolated user or store prefixes | System integration tests, `AGENTS.md` non-negotiable rules |

---

## 4. Explicit Compatibility Limitations

Dich adheres to a strict principle of **truth over demos**. It does **not** claim general Debian package relocatability. Users and beta testers must be fully aware of the following explicit limitations:

### 4.1 What Dich Is NOT
1. **Not a replacement for host `apt` or `dpkg`**: Dich does not install system-wide utilities, manage Linux services, install kernels, configure bootloaders, or update system glibc.
2. **Not an arbitrary binary relocator**: Traditional Linux binaries compiled for Debian/Ubuntu contain hardcoded interpreter paths (`/lib64/ld-linux-x86-64.so.2`), hardcoded data paths (`/usr/share/...`), and hardcoded configuration paths (`/etc/...`). Dich **does not** patch ELF binaries or rewrite RPATHs without an isolated runtime environment (ADR 0026).
3. **Not a systemd or daemon manager**: Services, systemd units, SysV init scripts, udev rules, D-Bus service configs, and cron jobs inside `.deb` packages are ignored and unsupported.

### 4.2 Supported Package Class: x86-64 glibc DSO Closures
Currently, the only package class supported for installation and profile generation is:
- **x86-64 glibc Dynamic Shared Objects (DSOs)**:
  - Single libraries or closed sets of shared libraries without host integration markers.
  - No maintainer scripts or service files.
  - Acyclic internal dynamic dependencies (`DT_NEEDED`).
  - Strict symbol namespace isolation via `dlmopen` or explicit path loading.
  - Packages violating these constraints are conservatively rejected with machine-readable diagnostic errors (`supported: false`, `reason: unsupported_feature`).

### 4.3 Unsupported Scenarios (Fail-Closed)
The following package characteristics result in immediate, fail-closed refusal to install:
- **Maintainer scripts present**: Packages with executable scripts are classified as `unsupported`.
- **System configuration files**: Packages modifying `/etc` or installing daemon configs are rejected.
- **Cross-distribution mixing**: Attempting to combine packages from Ubuntu Noble with Debian Bookworm, or different release suites, fails closed.
- **Unverified repositories**: Unsigned repositories, invalid GPG signatures, or mismatched checksums fail closed.
- **Architecture mismatches**: Foreign architectures (e.g., `arm64`, `i386` on `amd64`) are rejected.
