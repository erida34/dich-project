# Dich

**Dich** is an experimental, version-aware Linux package store that sources **original signed Debian and Ubuntu APT repositories and `.deb` artifacts** without assuming arbitrary binary packages are relocatable. Written in Rust.

It allows multiple package versions and configurations to coexist safely in immutable content-addressed storage, deduplicates shared dependencies, tracks exact reference graphs, supports atomic profile switching and instant rollbacks, and provides safe mark-and-sweep garbage collection.

Dich strictly adheres to the principle of **host non-interference**: it never invokes `apt` or `dpkg` on the host, never executes maintainer scripts (`postinst`, `preinst`), and never touches `/usr`, `/etc`, or `/var/lib/dpkg`.

---

## Key Features

- **Russian CLI help**: Use `dich --lang ru --help` or set `DICH_LANG=ru`; English remains the default. Russian man pages are installed under `/usr/share/man/ru/man1/`.

Russian help is available for commands too, for example `dich fetch --lang ru --help`. Set `DICH_LANG=ru` to make Russian the default for the current shell. At this stage, help, generated man pages, and mapped human-readable diagnostics are translated; successful command output, structured logs, JSON, and shell completions remain English.

- **Original APT Repositories**: Directly sources official upstream Debian and Ubuntu mirrors using cryptographic OpenPGP signature verification (`InRelease`, `Release.gpg`), digest validation, and rollback protection.
- **Content-Addressed Store**: Deduplicates shared libraries and files across package versions in read-only (`0400`) storage.
- **Authenticated DSO Profiles**: Selects narrowly supported x86-64 glibc DSO closures into versioned profiles and returns explicit library paths. Dich does not execute package code; the `dlmopen` fixture demonstrates symbol-namespace isolation only, not a process sandbox.
- **Atomic Profiles & Rollback**: Profiles are managed via atomic relative symlink switches pointing to cryptographic generation manifests. Instant rollback restores previous generation states.
- **Mark-and-Sweep Garbage Collection**: Safely identifies and sweeps unreachable objects while preserving all active profiles, rollback chains, and explicit pins. Defaults to `--dry-run`.
- **Rootless by Default**: Operates completely unprivileged in user environments following XDG standards (`$XDG_DATA_HOME/dich`, `$XDG_CACHE_HOME/dich`, `$XDG_CONFIG_HOME/dich`). No background daemons or setuid binaries.
- **Network Resilience & Offline Mode**: Exponential backoff retries, configurable bandwidth pacing (`--max-bandwidth`), preflight disk checks, and strict `--offline` mode refusing all socket traffic.
- **Structured Diagnostics**: Clean stdout/stderr separation, machine-readable versioned JSON (`--json`), structured logging (`--log-level`), and stable numeric exit codes.

---

## Supported Distribution Matrix

Dich verifies packages against explicit glibc and native architecture baselines (see [Support Matrix](docs/support-matrix.md) and [ADR 0036](docs/adr/0036-distribution-support-matrix-and-targets.md)):

| Distribution | Suite Codename | Architecture | glibc Baseline | Status |
|---|---|---|---|---|
| **Debian 12** | `bookworm` | `amd64` (x86_64) | 2.36 | Supported |
| **Debian 13** | `trixie` | `amd64` (x86_64) | 2.40 | Supported |
| **Ubuntu 22.04 LTS** | `jammy` | `amd64` (x86_64) | 2.35 | Supported |
| **Ubuntu 24.04 LTS** | `noble` | `amd64` (x86_64) | 2.39 | Supported |

*Note*: Moving suite aliases (`stable`, `testing`, `unstable`, `sid`, `devel`) and cross-distribution mixing within a profile are strictly rejected to ensure deterministic cryptographic reproducibility.

---

## Installation

### From Debian Package (`.deb`)
Download the release artifact `dich_<upstream-version>-<debian-revision>_amd64.deb` from GitHub Releases (for example, `dich_0.7.3-1_amd64.deb`):
```sh
sudo dpkg -i dich_<upstream-version>-<debian-revision>_amd64.deb
```
This installs the `dich` binary to `/usr/bin/dich`, documentation to `/usr/share/man/man1/dich.1.gz`, and shell completions for Bash, Zsh, and Fish.
During installation, Debian's configuration dialog offers to enable the official archive for supported Debian 12/13 or Ubuntu 22.04/24.04 amd64 systems. The default answer creates a signed-source policy using the system archive keyring and a pinned signing fingerprint. Noninteractive installs use that same default. Answering no leaves sources unconfigured; unsupported systems also install without a source. Existing configuration is never overwritten.

### From Source
Ensure Rust 1.85+ is installed:
```sh
git clone https://github.com/dich-project/dich.git
cd dich
cargo build --release
sudo cp target/release/dich /usr/local/bin/
```

### Uninstallation
To remove Dich completely:
```sh
# Remove binary and system package
sudo apt remove dich    # or: sudo dpkg -r dich

# Clean up system store and cache (if used)
sudo rm -rf /var/lib/dich /var/cache/dich /etc/dich

# Clean up user rootless store and cache (if used)
rm -rf ~/.local/share/dich ~/.cache/dich ~/.config/dich
```

---

## Configuration

Dich relies on explicit source policy files defining trusted APT repositories and their OpenPGP keyrings. To create the supported official default later (or after answering no during installation), run:

```sh
sudo dich setup
```

The command writes `/etc/dich/sources.toml` and `/etc/dich/sources/official.sources` without replacing existing files. It supports only Debian 12/13 and Ubuntu 22.04/24.04 on amd64. It does not import arbitrary host APT repositories. On unsupported distributions, configure a source manually using the policy below.

### Rootless Mode (User Configuration)
Create `~/.config/dich/sources.toml`:
```toml
[[sources]]
distribution = "debian"
sources_file = "/home/user/.config/dich/debian.sources"
uri = "https://deb.debian.org/debian"
suite = "bookworm"
components = ["main"]
architecture = "amd64"
keyring = "/usr/share/keyrings/debian-archive-keyring.gpg"
fingerprints = [
    "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8"
]
```

Create the referenced deb822 file `~/.config/dich/debian.sources`:
```deb822
Types: deb
URIs: https://deb.debian.org/debian
Suites: bookworm
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
```

### System Mode (`/etc/dich/sources.toml`)
For managed multi-user or system installations, place configuration in `/etc/dich/sources.toml`. When running unprivileged, Dich automatically falls back to reading `/etc/dich/sources.toml` if user configuration does not exist.

---

## Quickstart & Common Workflows

### 1. Refresh Repository Metadata
Fetch and cryptographically authenticate `InRelease` and package indices:
```sh
dich update
```
Release metadata is limited to 24 hours by default. A signed `Valid-Until` is enforced when present; repositories without that field use the same 24-hour signed-date limit. Use `--require-valid-until` for stricter policy, or override the age with `--max-age-seconds`.
For explicit offline environments:
```sh
dich --offline search openssl
```

### 2. Search and Query Cached Packages
Search package names and inspect version records:
```sh
dich search libsqlite3
dich show libsqlite3-0
dich versions libsqlite3-0
```

### 3. Dependency Planning
Generate a dependency and closure plan without installing:
```sh
dich plan libexample --distribution debian --suite bookworm --architecture amd64
```

### 4. Install a Package into a Profile
Dich plans by default. Use `--yes` to confirm and commit:
```sh
# Preview the install plan
dich install libexample --profile myapp --exact-version 1.2.0-1

# Commit the installation into the profile
dich install libexample --profile myapp --exact-version 1.2.0-1 --yes
```

### 5. Profile Management & Rollback
Inspect active profiles and generations:
```sh
dich profile list
```
Roll back a profile to its previous generation atomically:
```sh
# Preview rollback
dich rollback --profile myapp

# Commit rollback
dich rollback --profile myapp --yes
```
Remove a package profile:
```sh
dich remove libexample --profile myapp --yes
```

### 6. Garbage Collection
Reclaim unreferenced store objects while protecting active profiles and rollback targets:
```sh
# Dry run: preview reclaimable disk space
dich gc

# Execute: delete unreachable objects and fsync metadata
dich gc --execute
```

### 7. Inspect Local `.deb` Archives
Examine local archives safely without extraction or script execution:
```sh
dich inspect ./package.deb
dich --json inspect ./plugin.deb --with ./libcommon.deb
```

---

## Documentation

- [Architecture & Boundaries](docs/architecture.md)
- [Security Model & Threat Invariants](docs/security.md)
- [Distribution Support Matrix](docs/support-matrix.md)
- [Frequently Asked Questions (FAQ)](docs/faq.md)
- [Architecture Decision Records (ADRs)](docs/adr/)
- [Progress & Implementation Log](docs/progress.md)

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE-APACHE](LICENSE-APACHE).
