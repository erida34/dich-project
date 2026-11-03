# Dich

**Dich** is a production-oriented, version-aware Linux package store that sources **original signed Debian and Ubuntu APT repositories and `.deb` artifacts** without assuming arbitrary binary packages are relocatable. Written in Rust.

It allows multiple package versions and configurations to coexist safely in immutable content-addressed storage, deduplicates shared dependencies, tracks exact reference graphs, supports atomic profile switching and instant rollbacks, and provides safe mark-and-sweep garbage collection.

Dich strictly adheres to the principle of **host non-interference**: it never invokes `apt` or `dpkg` on the host, never executes maintainer scripts (`postinst`, `preinst`), and never touches `/usr`, `/etc`, or `/var/lib/dpkg`.

---

## Key Features

- **Original APT Repositories**: Directly sources official upstream Debian and Ubuntu mirrors using cryptographic OpenPGP signature verification (`InRelease`, `Release.gpg`), digest validation, and rollback protection.
- **Content-Addressed Store**: Deduplicates shared libraries and files across package versions in read-only (`0400`) storage.
- **Isolated DSO Execution**: Allows applications to load isolated DSO closures into independent link-map namespaces (`dlmopen(LM_ID_NEWLM)`), preventing symbol collision and host library conflicts without binary patching.
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
Download the release artifact `dich_<upstream-version>-<debian-revision>_amd64.deb` from GitHub Releases (for example, `dich_0.1.0-1_amd64.deb`):
```sh
sudo dpkg -i dich_<upstream-version>-<debian-revision>_amd64.deb
```
This installs the `dich` binary to `/usr/bin/dich`, documentation to `/usr/share/man/man1/dich.1.gz`, and shell completions for Bash, Zsh, and Fish.

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

Dich relies on explicit source policy files defining trusted APT repositories and their OpenPGP keyrings.

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
    "B42F2F2309C104E9833606C7A87A134DE3532297"
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

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
