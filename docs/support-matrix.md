# Distribution and Platform Support Matrix

This document defines the supported operating environments, distribution releases, architectures, and package categories for Dich v0.7.x / v1.0.0.

## Tier 1 Supported Platforms

Tier 1 platforms are continuously tested in automated regression suites and verified against signed upstream APT repository structures.

| Distribution | Suite Codename | Architecture | glibc Version | Status |
|---|---|---|---|---|
| **Debian 12** | `bookworm` | `amd64` (x86_64) | 2.36 | Fully Supported |
| **Debian 13** | `trixie` | `amd64` (x86_64) | 2.40 | Fully Supported |
| **Ubuntu 22.04 LTS** | `jammy` | `amd64` (x86_64) | 2.35 | Fully Supported |
| **Ubuntu 24.04 LTS** | `noble` | `amd64` (x86_64) | 2.39 | Fully Supported |

## Supported Package Category

In accordance with [ADR 0025](adr/0025-standalone-dso-allowlist.md) and [ADR 0029](adr/0029-authenticated-dso-profile-install.md):
- **Dynamic Shared Objects (DSOs)**: Standalone `.so` libraries and acyclic DSO closures matching native `amd64` glibc ABI.
- **Profile behavior**: Dich authenticates, stores and selects supported DSO closure paths. The CLI does not load or execute package code. A `dlmopen(LM_ID_NEWLM)` fixture demonstrates symbol-namespace isolation only; it is not a process sandbox. No ELF patching or host `/usr` / `/etc/ld.so.conf` changes are performed.

## Explicitly Unsupported Targets

Dich is designed to fail closed when presented with unsupported distributions, moving targets, or unsafe packages:

### 1. Moving or Rolling Suite Aliases
Dich requires immutable, versioned release suites. Using moving aliases causes immediate policy rejection:
- ❌ `stable`, `oldstable`, `oldoldstable`
- ❌ `testing`, `unstable`, `sid`
- ❌ `devel`, `rolling`, `experimental`

*Reason*: Moving suites change package contents dynamically without cryptographic snapshot pinning, breaking rollback guarantees and deterministic resolution.

### 2. Cross-Distribution or Mixed-Suite Profiles
- ❌ Mixing Debian packages with Ubuntu packages in the same profile.
- ❌ Mixing Debian `bookworm` with Debian `trixie` in the same profile.
- ❌ Mixing Ubuntu `jammy` with Ubuntu `noble` in the same profile.

*Reason*: Glibc and standard C++ library ABIs are not guaranteed to be forward- or backward-compatible across major distribution releases.

### 3. Non-Debian / Non-Ubuntu Linux Distributions
- ❌ Alpine Linux (musl libc is incompatible with glibc DSOs).
- ❌ Red Hat / CentOS / Fedora / Rocky Linux (RPM packaging model).
- ❌ Arch Linux / Void / Gentoo (rolling release / rolling ABI).
- ❌ NixOS / Guix (declarative store with non-standard loader paths).

### 4. Non-Native Architectures
- ❌ `i386` (32-bit x86).
- ❌ `arm64` (aarch64) on x86_64 hosts (supported only on native arm64 hardware when verified).
- ❌ `armhf`, `riscv64`, `s390x`, `ppc64el`.

### 5. Arbitrary Non-Relocatable Debian Packages
- ❌ Packages containing executable binaries expecting hardcoded `/usr/bin` paths.
- ❌ Packages requiring systemd services, daemons, udev rules, or D-Bus system bus policies.
- ❌ Packages with maintainer scripts (`preinst`, `postinst`, `prerm`, `postrm`) or dpkg triggers.
