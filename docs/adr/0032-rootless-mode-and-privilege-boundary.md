# ADR 0032 — Rootless development mode and minimal privilege boundary

Status: Accepted for Phase 6 hardening and operational quality.

## Context

Dich is designed to install and manage versioned packages and execution profiles from original signed Debian/Ubuntu APT repositories without modifying `/usr` or invoking host package managers (`apt`, `dpkg`).

Developers building, testing, or consuming packages require running Dich without superuser privileges (`root` or `sudo`). In developer environments, user workspaces, and continuous integration pipelines, requiring superuser privileges creates unnecessary security hazards and friction.

At the same time, Dich must support managed system installations where administrators configure trusted system repositories in `/etc/dich` and publish system-wide profiles in `/var/lib/dich`.

The project roadmap calls for:
> Rootless mode for development; privileged operations mediated by minimal audited boundary (daemon only if justified).

## Decision

### 1. Rejection of Privileged Background Daemon
A background daemon, setuid binary, or root privilege broker is **explicitly rejected as unjustified**.
- Dich never executes `.deb` maintainer scripts by default, does not touch host `/etc` or `/usr`, does not modify global `ld.so.conf`, and does not register system daemons.
- Introducing a background daemon would require IPC, authentication protocols, socket management, and access control lists, significantly expanding the attack surface and introducing potential privilege escalation vulnerabilities.
- Privileged operations (modifying system store `/var/lib/dich`, system cache `/var/cache/dich`, or `/etc/dich`) are mediated directly by standard process privilege inheritance (e.g. running Dich under `sudo`).
- In rootless mode, all operations (network fetch, GPG verification via `gpgv`, staging, ELF validation, SQLite metadata transactions, profile switching, and garbage collection) run entirely unprivileged under the user's UID.

### 2. Standard XDG User Base Directories for Rootless Mode
In rootless mode, Dich adheres to the XDG Base Directory Specification:
- **Configuration**: `$XDG_CONFIG_HOME/dich/sources.toml` (defaulting to `~/.config/dich/sources.toml`). If this file does not exist, Dich checks if the system configuration `/etc/dich/sources.toml` exists and is readable, using it as a read-only fallback so unprivileged users can immediately query and consume official distro repositories without duplicating config files.
- **Cache**: `$XDG_CACHE_HOME/dich` (defaulting to `~/.cache/dich`).
- **Store Directory**: `$XDG_DATA_HOME/dich` (defaulting to `~/.local/share/dich`).

### 3. Mode Selection and CLI Flags
- `--rootless`: Explicitly forces rootless mode using XDG base directories, even if executed as UID 0.
- `--system`: Explicitly forces system mode (`/etc/dich`, `/var/cache/dich`, `/var/lib/dich`).
- Explicit paths (`--config <PATH>`, `--cache <PATH>`, `--store-dir <PATH>`) always take precedence over default mode paths.
- Default behavior when neither `--rootless` nor `--system` is specified:
  - If `geteuid() != 0` (unprivileged user): rootless mode is automatically selected.
  - If `geteuid() == 0` (superuser): system mode is selected.

### 4. Safe Rootless Directory Initialization
- Mutating commands (`update`, `install`, `fetch --publish-tree`, `remove`, `rollback`, `gc --execute`) ensure that the target cache or store directory exists before opening.
- Path traversal is strictly descriptor-relative (`openat` with `O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC`):
  - Every parent component must be owned by `root` (UID 0) or the current user (`geteuid()`) and must not be group-writable or world-writable (`mode & 0022 == 0`).
  - Missing intermediate user-owned components and the leaf directory are created with mode `0700` (`rwx------`).
  - If an unprivileged user attempts to modify or create a path in a directory they do not own (such as `/var/lib` or `/var/cache`), the operation fails closed with a clear diagnostic hint explaining that the path requires privileges or rootless mode.
- Read-only commands (`search`, `show`, `versions`, `store ls`, `store verify`, `profile list`) never create directories on disk, reporting clean diagnostics if the store or cache has not yet been initialized.

### 5. Staging Environment Compatibility
In `dich-deb::stage_cached`, the `/tmp` ownership verification is relaxed from requiring `stat.st_uid == 0` to `stat.st_uid == 0 || stat.st_uid == geteuid().as_raw()`, while still requiring sticky bit `01000` if writable by group or others. This allows rootless containers and user namespaces to stage archives safely without error.

## Consequences

- Unprivileged developers can run `dich` commands out of the box without `sudo` or special setup.
- The system remains completely protected against unprivileged tampering.
- No background daemon or socket broker is introduced, maintaining a minimal and auditable security boundary.
