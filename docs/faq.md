# Frequently Asked Questions (FAQ)

## General Concepts

### What is Dich?
Dich is a versioned, immutable Linux package store that sources original signed Debian and Ubuntu APT repositories and `.deb` packages. It allows multiple package versions to coexist side-by-side in content-addressed storage, deduplicates shared dependencies, supports atomic profile switching and rollbacks, and provides safe mark-and-sweep garbage collection.

### How is Dich different from system `apt` and `dpkg`?
Standard `apt install` or `dpkg -i` mutates the global `/usr` filesystem and host dpkg database in place. It cannot install multiple versions of the same package simultaneously (e.g., `libssl.so.1.1` and `libssl.so.3` from different distributions or versions). 
Dich never touches host `/usr`, `/etc`, or `/var/lib/dpkg`. Dich installs packages into isolated, read-only content-addressed directories (`/var/lib/dich` or `~/.local/share/dich`) without interfering with host operating system stability.

### How is Dich different from Nix or Guix?
- **Upstream Sources**: Nix and Guix require compiling packages from source or downloading custom binary caches using custom DSLs (`.nix`, Scheme). Dich sources original, pre-compiled, cryptographically signed `.deb` artifacts directly from official Debian and Ubuntu mirrors.
- **Relocation Reality**: Dich does not assume arbitrary Linux packages can be magically relocated with rewritten rpaths without validation. It explicitly audits packages for absolute path assumptions, services, triggers, and maintainer scripts before admission.

### Why does Dich not run `.deb` maintainer scripts (`postinst`, `preinst`)?
Debian maintainer scripts are arbitrary shell or Perl scripts designed to run as `root` with complete access to host system state (modifying `/etc`, adding system users, registering systemd services). Running maintainer scripts from untrusted or user-staged packages would compromise host isolation and rootless security. In Dich, maintainer scripts are treated as audit metadata only and are never executed on the host.

---

## Architecture and Supported Packages

### What package types can be installed in Dich?
In v0.7.x / v1.0, Dich supports authenticated **Dynamic Shared Objects (DSOs)** and acyclic DSO closures matching native `amd64` glibc ABI (ADR 0025, ADR 0027, ADR 0029). These libraries are executed in isolated link-map namespaces (`dlmopen(LM_ID_NEWLM)`), ensuring safe coexistence without symbol collision. General arbitrary CLI binaries and daemons expecting fixed `/usr/bin` host paths or system services are rejected.

### Can I mix packages from Debian and Ubuntu?
No. Dich strictly rejects cross-distribution and cross-suite mixing within a profile (e.g., mixing Debian `bookworm` with Ubuntu `noble`). Glibc and libstdc++ ABIs differ between distributions, and mixing them introduces silent binary incompatibilities.

### Can I use rolling suites like `sid` or `testing`?
No. Moving aliases (`stable`, `testing`, `unstable`, `sid`, `devel`) are rejected by policy. Sources must declare immutable suite codenames (e.g. `bookworm`, `trixie`, `jammy`, `noble`) to ensure cryptographic snapshot repeatability and prevent rollback attacks.

---

## Privileges and Operation

### Does Dich require a background daemon or `sudo`?
No. Dich rejects background daemons and setuid binaries (ADR 0032). 
- In **rootless mode** (automatic for non-root users), Dich operates entirely within the user's home directory following XDG standards (`~/.local/share/dich`, `~/.cache/dich`, `~/.config/dich`).
- In **system mode** (`sudo dich --system ...`), Dich writes to standard system locations (`/var/lib/dich`, `/var/cache/dich`, `/etc/dich`).

### How does rollback work?
Every `dich install` or `dich remove` transaction creates an immutable, content-addressed generation manifest in `profiles/<name>/generations/<sha256>`. The active generation is pointed to by a relative symlink `profiles/<name>/current`. 
Running `dich rollback --profile <name> --yes` atomically swaps the `current` symlink to the previous recorded generation manifest.

### How does Garbage Collection (GC) work?
`dich gc` implements mark-and-sweep garbage collection:
1. **Mark Phase**: Traverses active profile pointers (`current` symlinks) and their complete ancestor rollback chains (`previous_id`), plus explicit pins. All trees and graphs referenced by active profiles or rollback targets are marked as reachable.
2. **Sweep Phase**: Any stored tree object or reference graph not reachable from active roots is identified as unreachable.
3. **Safety**: `dich gc` defaults to dry-run reporting reclaimable disk space. Only `dich gc --execute` deletes unreachable objects from disk.

### How does offline mode work?
With `--offline`, Dich completely blocks network socket initialization (`OfflineTransport`). If all required package artifacts and signed snapshot indices are already present in the local cache, queries, planning, and installation proceed completely offline without network access.

---

## Uninstallation and Cleanup

### How do I uninstall Dich and clean up its data?
1. Remove the Dich binary or package:
   - System `.deb`: `sudo apt remove dich` or `sudo dpkg -r dich`
   - Cargo / manual build: `rm /usr/local/bin/dich` or `rm ~/.cargo/bin/dich`
2. Remove system store and cache (if used):
   - `sudo rm -rf /var/lib/dich /var/cache/dich /etc/dich`
3. Remove user rootless store and cache (if used):
   - `rm -rf ~/.local/share/dich ~/.cache/dich ~/.config/dich`
