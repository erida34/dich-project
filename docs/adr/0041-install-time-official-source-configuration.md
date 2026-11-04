# ADR 0041 — Install-time official source configuration

Status: Accepted.

## Context

A fresh package installation previously left `/etc/dich/sources.toml` absent, so commands such as `dich update` stopped before repository verification. Automatically trusting arbitrary host APT sources would silently expand Dich's trust boundary.

## Decision

The `.deb` asks whether to configure the detected official archive, with `yes` as the debconf default. Noninteractive installation uses this default. `dich setup` supports only Debian 12 Bookworm, Debian 13 Trixie, Ubuntu 22.04 Jammy and Ubuntu 24.04 Noble on amd64. Each mapping fixes the HTTPS URI, suite, main component, system archive keyring and full signing fingerprint. No host APT source is imported. The generated policy and Deb822 file are created exclusively; an existing file is never replaced. Unsupported systems, a missing/unsafe keyring, or a `no` answer leave Dich installed without a source policy.

The source configuration describes trust; it does not authenticate the repository at setup time. `dich update` still has to verify signed Release metadata, freshness and all referenced digests before using package indices or artifacts.

## Consequences

- A normal supported installation has a usable source policy without manual file editing.
- Noninteractive installs do not block on a prompt and take the documented default.
- The trusted fingerprint mapping must be reviewed when archive keys rotate. Changes require authoritative fingerprint verification and release-matrix smoke tests.
- This does not enable third-party repositories, unsupported suites or architectures, unsigned metadata, or arbitrary `.deb` installation.
