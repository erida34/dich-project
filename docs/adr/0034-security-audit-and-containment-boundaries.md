# ADR 0034 — Security Audit: Key Handling, Filesystem/TOCTOU, Paths, Privilege Model, and Container Limits

Status: Accepted for Phase 6 hardening and operational quality.

## Context

Dich sources Debian and Ubuntu APT repositories and `.deb` archives directly without trusting the host `/usr` or invoking host package managers (`apt`, `dpkg`). It operates in both unprivileged developer environments (rootless mode via XDG paths) and managed system environments (`/var/lib/dich`).

Because Dich processes untrusted network metadata, untrusted cryptographic signatures, untrusted tar/ar archive streams, and complex ELF binaries, it must withstand hostile environments, malicious repositories, adversarial local users sharing the filesystem, and restrictive container sandbox environments.

The roadmap requires:
> Security review of key handling, filesystem/TOCTOU attacks, paths, symlinks, privilege model and container limits.

## Decision and Audit Matrix

A comprehensive security review across five core vulnerability classes was conducted:

### 1. Key Handling and Cryptographic Trust
- **Isolation of Keyrings**: Dich never relies on ambient `/etc/apt/trusted.gpg` or unauthenticated key servers. Repositories must declare explicit `Signed-By` keyrings in `sources.toml` or deb822 source files.
- **Keyring Path Verification**: Keyrings are opened exclusively via `openat_nofollow_path`, traversing each directory component with `O_NOFOLLOW | O_DIRECTORY`. Every component must be owned by `root` (UID 0) or the invoking user and must not be group-writable or world-writable. Symlinks anywhere in the keyring path are strictly rejected.
- **Process Isolation for GPG**: Cryptographic signature validation is delegated to `/usr/bin/gpgv` executed in an isolated subprocess with an explicit, synthetic keyring containing only the authorized key(s). Subprocesses are constrained using `prlimit(2)` with strict ceilings on address space (`RLIMIT_AS`), CPU time (`RLIMIT_CPU`), output file size (`RLIMIT_FSIZE`), and open descriptors (`RLIMIT_NOFILE`), preventing decompression bombs or algorithmic complexity attacks from exhausting host resources.
- **Strict Key Binding**: Subkeys must be cryptographically bound to an authorized primary key fingerprint. Revoked, expired, or untrusted keys fail closed. In detached mode or multi-signature repositories, all signers must be explicitly authorized; any unauthorized signature fails closed.

### 2. Filesystem and TOCTOU Attacks
- **Descriptor-Relative Traversal**: Path lookups and directory operations never use ambient string concatenation across untrusted boundaries. Operations use `openat(2)` and `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`.
- **Atomic File and Directory Creation**: All temporary files are created with `O_CREAT | O_EXCL | O_CLOEXEC` and permissions `0600` in dedicated private staging directories (`0700`). Directory and profile generation switches use atomic `rename(2)` or `renameat2(2)` with directory `fsync` barriers before and after publication.
- **Symlink and Hardlink Rejection**:
  - Symlinks in the cache directory, store directory, metadata SQLite database, WAL files, or lock files are rejected unconditionally.
  - Hardlinks (`st_nlink > 1`) on metadata databases, WAL files, or lock files are rejected to prevent hardlink spoofing or unauthorized concurrent mutation.
  - Store objects and profile generation manifests are stored with mode `0400` (read-only), preventing accidental in-place mutation.
- **TOCTOU Mitigation in Staging**: Archive staging extracts files strictly beneath a freshly created, randomized private directory in `/tmp` (verified to have mode `0700` and owned by root or current user). Extraction uses descriptor-relative creation with openat2 flag `RESOLVE_BENEATH`.

### 3. Path Traversal and Archive Containment
- **Path Sanitization**: All archive member names are validated before extraction. Any entry containing absolute paths (`/`), directory traversal segments (`..`), empty components, NUL bytes, or control characters (`< 0x20`) is rejected.
- **Link Escapes**: Hardlinks and symlinks within `.deb` archives are rejected in Phase 3/4 staging. Symlink extraction into the package tree is completely disallowed; package files are regular files or directories only.
- **Store Path Addressing**: Store trees are content-addressed (`store/objects/trees/<sha256>`). Path lookups are checked against expected hex digests. Traversal outside the object directory is structurally impossible.

### 4. Privilege Model and Defense-in-Depth
- **No Background Daemon or Setuid**: Dich operates strictly as a foreground CLI with standard process inheritance. No setuid binaries, ambient capabilities, or root background services exist.
- **Privilege Separation**: Unprivileged users run in rootless mode, confined to `$XDG_DATA_HOME/dich` (`~/.local/share/dich`), `$XDG_CACHE_HOME/dich` (`~/.cache/dich`), and `$XDG_CONFIG_HOME/dich` (`~/.config/dich`).
- **Private Permissions**: All created directories enforce mode `0700` (`rwx------`). Staged files enforce `0600` (`rw-------`). Committed store files enforce `0400` (`r--------`).
- **No Maintainer Script Execution**: Debian maintainer scripts (`preinst`, `postinst`, `prerm`, `postrm`) and triggers are parsed as diagnostic metadata only and are never executed on the host. Host `/usr`, `/etc`, and `/var/lib/dpkg` remain completely untouched.

### 5. Container Limits and Resource Exhaustion
- **Resource Limits (rlimits)**: Dich handles low file descriptor limits (`RLIMIT_NOFILE`) gracefully without leaking descriptors or panicking. Helper processes are bounded by `prlimit`.
- **Disk Space Preflight**: Before downloading or staging artifacts, Dich inspects available filesystem blocks via `statvfs(3)` to ensure sufficient capacity (minimum 50 MB required), avoiding partial writes and corrupted states.
- **Container Runtime Compatibility**: Staging directory verification supports standard user namespaces, Podman rootless, and Docker environments where `/tmp` is owned by the container user.

## Verification

Adversarial integration and unit tests verify these security invariants:
1. `key_handling_adversarial`: Keyring path with symlinks rejected; forged or tampered keyrings fail closed; invalid subkeys rejected.
2. `filesystem_toctou_adversarial`: Attempted symlink substitution of store paths and database sidecars; hardlink injection on metadata database files; permission tampering detection.
3. `path_traversal_adversarial`: Archives with directory escape (`../`), absolute paths, and null bytes rejected.
4. `privilege_and_container_limits`: Rootless execution under constrained file descriptor limits (`rlimit`), container-like user namespaces, and read-only file protection.

## Consequences

- The security perimeter of Dich is formally defined and verified under adversarial conditions.
- System integrity cannot be compromised by malicious upstream repositories, tampered `.deb` archives, or local filesystem races.
