# ADR 0036 — Distribution Support Matrix and Unsupported Targets

Status: Accepted for Phase 6 hardening and operational quality.

## Context

Dich sources Debian and Ubuntu APT repositories and packages without assuming that arbitrary packages are relocatable. Different Linux distributions and releases use varying glibc ABIs, packaging conventions, path layouts, and cryptographic keyrings.

To ensure deterministic, reliable package management without silent ABI breakage, Dich must establish an explicit, verified distribution support matrix and define clear boundaries for unsupported targets.

The project roadmap requires:
> Integration tests on supported Debian/Ubuntu LTS/current releases; documented support matrix and unsupported targets.

## Decision

### 1. Supported Operating Systems and Releases (v1.0 Baseline)

| Distribution | Release Suite | glibc Baseline | Architecture | Support Level |
|---|---|---|---|---|
| **Debian 12** | `bookworm` | 2.36 | `amd64` (x86_64) | Tier 1 (Supported & Verified) |
| **Debian 13** | `trixie` | 2.40 | `amd64` (x86_64) | Tier 1 (Supported & Verified) |
| **Ubuntu 22.04 LTS** | `jammy` | 2.35 | `amd64` (x86_64) | Tier 1 (Supported & Verified) |
| **Ubuntu 24.04 LTS** | `noble` | 2.39 | `amd64` (x86_64) | Tier 1 (Supported & Verified) |

### 2. Supported Package Execution Model

In accordance with ADR 0025, ADR 0027, and ADR 0029:
- **Allowlisted Subset**: Standalone DSOs and self-contained DSO closures built for Linux x86-64 with glibc.
- **Loading Mechanism**: Isolated dynamic linker namespaces (`dlmopen(LM_ID_NEWLM)`), ensuring symbol isolation without modifying host libraries or `/etc/ld.so.conf`.
- **Execution Privileges**: Standard process permissions of the invoking user or container.

### 3. Unsupported Targets and Rejection Boundaries

The following targets and configurations are **strictly rejected**:

1. **Non-Debian / Non-Ubuntu Distributions**:
   - RPM distributions (Fedora, RHEL, CentOS, Rocky, Alma, OpenSUSE).
   - Musl distributions (Alpine, Void Musl).
   - Declarative distributions (NixOS, Guix).
   - Rolling distributions (Arch Linux, Gentoo).
2. **Moving / Rolling Suite Aliases**:
   - `stable`, `oldstable`, `testing`, `unstable`, `sid`, `experimental`, `devel`, `rolling`.
   - Operators must configure immutable suite codenames (`bookworm`, `trixie`, `jammy`, `noble`) to ensure cryptographic snapshot repeatability and prevent rollback vulnerability evasion.
3. **Cross-Distribution and Multi-Suite Mixing**:
   - Combining Debian and Ubuntu sources within a single profile is forbidden.
   - Mixing packages across different release suites (e.g. `jammy` packages inside a `noble` profile) is rejected at plan and install admission.
4. **Foreign Architectures without Native Runtime**:
   - `i386`, `arm64`, `armhf`, `riscv64`, `s390x`, `ppc64el` on x86_64 hosts are rejected. Cross-architecture emulation without hardware support is not authorized.
5. **General Arbitrary `.deb` Packages**:
   - Executables with hardcoded absolute `/usr/bin`, `/etc`, or `/var` paths.
   - Packages declaring systemd services, init scripts, udev rules, or D-Bus system bus configurations.
   - Packages executing maintainer scripts (`preinst`, `postinst`, `prerm`, `postrm`) or dpkg triggers.

## Verification

Integration tests in `crates/dich-cli/tests/distro_integration.rs` verify:
1. Valid configuration, update, and plan resolution for Debian `bookworm` and `trixie`.
2. Valid configuration, update, and plan resolution for Ubuntu `jammy` and `noble`.
3. Immediate rejection of moving suite aliases (`sid`, `unstable`, `testing`, `devel`).
4. Rejection of mixed distribution suites in a single profile.
5. Rejection of unsupported architectures (`arm64`, `i386`).

## Consequences

- Clear expectations are set for users and administrators.
- Fail-closed admission policies prevent subtle runtime bugs and symbol conflicts.
