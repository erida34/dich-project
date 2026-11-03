# ADR 0040 — Beta Testing Framework, Issue Triage Taxonomy, Threat Model Review, and Compatibility Limitations

Status: Accepted for Phase 7 public release.

## Context

Phase 7 of the Dich roadmap mandates:
> External beta testers, issue triage, threat model review, compatibility limitations explicit.

Dich is a security-first versioned package store. Ensuring long-term stability and user trust requires formalizing external feedback channels, defining a clear triage taxonomy for reported bugs, conducting a comprehensive review of the threat model and defense implementations, and making runtime compatibility boundaries transparent.

## Decision

### 1. External Beta Program and Feedback
- Establish clear guidelines for beta testers in `docs/beta-testing-and-triage.md`.
- Target key user scenarios: rootless developer environments, profile rollback workflows, multi-source repository snapshots, safe garbage collection, and concurrency resilience.
- Require structured bug reports with environment details, exact CLI invocations, reproducible test cases, and machine-readable error codes.

### 2. Issue Triage Taxonomy and SLAs
Define an explicit four-tier bug severity taxonomy:
- **P0 - Critical Security**: Trust violations, signature bypass, path escapes, arbitrary code execution. Response target < 12 hours, patch fix < 48 hours via security release.
- **P1 - Data Corruption / Hang**: Database corruption, broken profile generations, GC deletion of live objects, deadlocks. Response target < 24 hours.
- **P2 - Resolver / Compatibility**: False positives in allowed DSO subset, backtracking errors, valid control parse failures. Response target < 3 days.
- **P3 - Minor / UX / Docs**: CLI formatting, documentation, non-blocking edge cases. Response target < 7 days.
- Security vulnerabilities must be disclosed responsibly according to `SECURITY.md`.

### 3. Threat Model Review
Conduct and document a comprehensive threat review covering:
- Repository metadata integrity (GPG signatures, InRelease validation, digest chaining).
- Network and transport security (TLS enforcement, expiration checks, anti-rollback floor checks).
- Archive envelope and payload containment (`openat2` traversal restrictions, size/byte limits, rate limits, `prlimit` bounds).
- Package lifecycle isolation (maintainer scripts are never executed).
- Filesystem and database durability (0700/0600 modes, 0400 object trees, exclusive `flock`, WAL mode, `synchronous = FULL`).
- Host isolation (no modifications to host `/etc`, `/usr`, or `/var/lib/dpkg`).

An internal repository-grounded review is recorded in [`dich-project-threat-model.md`](../../dich-project-threat-model.md), dated 2026-11-04. It is not an independent penetration test. It identifies signing-key and release-tag compromise, same-UID state tampering, parser resource exhaustion and the limits of DSO symbol isolation. It assumes a single trusted operator pending confirmation. External beta results and issue-triage records remain outstanding.

### 4. Explicit Compatibility Boundaries
- Declare explicitly what Dich is and is not: Dich is **not** a general-purpose replacement for `dpkg`/`apt`, does **not** perform arbitrary binary relocation, and does **not** manage system services/daemons.
- The supported installable package class is strictly bounded to **x86-64 glibc Dynamic Shared Object (DSO) closures** isolated via `dlmopen` or explicit path loading.
- Unsupported packages (maintainer scripts, system files, cross-distribution mixing, unauthenticated sources) fail closed with clear machine-readable diagnostic errors.

## Consequences

- Beta testers have a clear framework for exercising Dich safely and reporting issues effectively.
- Triage priorities ensure security and integrity defects receive immediate attention.
- Users are not misled by false assumptions regarding arbitrary `.deb` compatibility.
- GitHub private vulnerability reporting is enabled, so beta recruitment has a private disclosure route; `SECURITY.md` records that no separate maintainer email is configured.
