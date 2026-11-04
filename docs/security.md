# Security model

## Threats
Malicious or compromised mirror, wrong trusted key, tampered index/blob, repository rollback, malicious Debian archive paths/symlinks, decompression bombs, hostile ELF, `dlopen` surprises, absolute path assumptions, privilege escalation, TOCTOU, interrupted transactions, stale profile pointers, corrupted metadata, concurrent GC/install, disk exhaustion.

## Minimum controls
- Verify signed Release metadata bound to the configured repository and key; validate SHA256/size of every referenced index/package.
- Explicit per-source trust configuration, release expiration/Valid-Until and clock policy; fail closed when validation cannot be established.
- Archive extraction with strict size limits, no following symlinks, no device nodes, no privilege bits; reject paths escaping stage root.
- Never run maintainer scripts, triggers, arbitrary hooks, or fetched executable files on the host by default.
- Compatibility approval is not equivalent to source authenticity. Only a documented allowlist is installable.
- Keep daemon unnecessary until proven otherwise; future privilege broker has restricted RPC and authentication.
- Verify all path operations against races and use robust APIs (openat2 where available, safe fallback with clear limits).
- Record transformations and provenance, use structured errors and avoid accidental credential logging.

## Prohibited shortcuts
`apt --allow-unauthenticated`, `trusted=yes`, `--insecure`, `curl | sh`, global `LD_LIBRARY_PATH` changes, `chmod -R 777`, untrusted scripts, removing host libraries, executing root in a network build sandbox.

## Current source import boundary

The deb822 importer applies an operator-supplied source allowlist, bounds input, and rejects unsupported fields, missing `Signed-By`, and nonmatching signing fingerprints. Policy TOML parsing rejects unknown fields. The CLI source listing opens policy and source files without following symlinks and rejects unsafe ownership or writable paths; listing does not authenticate a repository. Its URI syntax checks are not a network or redirect security policy. Authenticated update, offline metadata queries, and exact-version artifact fetch are implemented. A narrow authenticated DSO profile install/remove/list/rollback path is implemented under ADR 0029; general Debian package installation and arbitrary dependency closures remain unsupported.

Package installation may offer (and defaults to) generating one source policy for the detected official archive on Debian 12/13 or Ubuntu 22.04/24.04 amd64. The mapping uses fixed HTTPS archive URIs, distro-provided keyrings and explicit fingerprints; it never imports arbitrary `/etc/apt` entries. `dich setup` uses the same allowlist, validates the generated policy and keyring path, creates files exclusively and refuses to replace pre-existing files. The debconf answer `no`, unsupported OS/suite/architecture or a missing/unsafe keyring leaves the package installed but without an automatically configured source. The default mapping is a trust anchor and must be reviewed when distro signing keys rotate.

The library signature verifier invokes `/usr/bin/gpgv` through `/usr/bin/prlimit` with an isolated temporary keyring and checks the reported signer against the configured fingerprints. The public verification APIs open each configured keyring path component without following symlinks and reject unsafe ownership, writable directories and non-regular keyrings. The CLI also securely loads the operator policy. Fixture tests cover revoked and expired keys. Fetch and cache operations check a persisted per-source rollback floor under a lock, subject to trusted-clock, protected-storage and suite-alias limitations documented in ADR 0007. Helper file, address-space, CPU, descriptor and wall-time limits are configured but have not been stress tested. Multiple signatures are accepted only if all are valid and their signers are allowed. Do not use signature success alone to authorize package installation.

The index verifier checks the compressed length and SHA256 against signed metadata before invoking gzip or xz under resource limits. Tests exercise altered, truncated, malformed and oversized compressed inputs. Both compressed input and expanded output are currently held in memory within configured bounds. Artifact transport requires HTTPS with validated TLS and confines redirects to the configured source origin and base path; size and SHA256 are checked while streaming to a temporary file. Cache reads reauthenticate Release and recheck index and artifact digests. Failure injection covers publication windows; real power-loss behavior remains unverified.

Control, relation and version parsing operate on bounded untrusted inputs. Parsed dependencies are descriptive data only; architecture restrictions, build profiles, alternatives and conflicts must be enforced by a future resolver before activation. Do not treat a successfully parsed version or dependency as ABI approval.

## Security review gate
No general `.deb` install support until there is a documented threat model, independent review of extraction/activation/GC paths, test corpus with hostile inputs, and crash/failure injection tests.

Update is not atomic across indices or sources; an error may leave a partially refreshed cache, and offline queries fail closed for missing or inconsistent data. A trusted clock and protected local cache are required. Removing or rolling back the entire cache can defeat its persisted rollback floor; suite aliases have separate floors. Cross-origin redirects and proxies are unsupported. Search results are metadata, not proof of safe installation.

Phase 1 regression coverage maps threats to executable tests:

- Forgery and wrong keys: `signature_tests::rejects_untrusted_signer_tampering_and_missing_trust` and `transport_tests::update_rejects_hostile_responses_without_publishing_an_index`.
- Rollback, equivocation and clock reversal: `cache_tests::rejects_equivocation_rollback_and_backwards_clock`; expiry/freeze: `rejects_expired_future_wrong_suite_or_origin`. This relies on protected state and a trustworthy clock; it cannot detect an attacker replaying a still-fresh snapshot after deleting the entire floor.
- Checksum mismatch, truncated streams and gzip/xz expansion limits: `rejects_mismatch_truncation_unapproved_paths_and_bomb`; the update-level test also checks that corrupt or truncated index bytes are not exposed as a cached index.
- Malicious artifact paths and redirects: `artifact::tests::rejects_url_escape_and_ambiguous_artifact_paths` and `transport_tests::redirect_policy_rejects_origin_escape_and_encoded_paths`.

These tests are scoped to the metadata and download pipeline, not extraction, installation, full system compromise or a substitute for independent security review.

The initial resolver policy (ADR 0009) compares exact distribution, suite and native architecture and rejects known moving aliases. The experimental single-source metadata planner applies it; an operator must select a genuinely immutable suite label; matching labels do not establish ABI compatibility. Freshness must be rechecked separately at use time.

Relationship parsing (ADR 0010) does not authorize packages or determine whether host packages satisfy dependencies. Essential and Priority: required are separate metadata flags; the experimental planner rejects essential/required candidates and does not use host state. A complete system-base policy is not implemented. Unsupported relation semantics, service integration and scripts remain blockers for installation.

Experimental plans contain authenticated Release and artifact identities, but are informational metadata results, not reusable installation locks or evidence of ABI compatibility. Plan inputs are rechecked before and after search; the cache is not a globally atomic snapshot and can change after a plan returns. Packages with unsupported multiarch qualifiers or essential/required classification are not planned. Pre-Depends are included in the search, but cycles involving them are conservatively rejected and no installation order is produced. Direct `:any` dependencies require a native candidate marked Multi-Arch: allowed; virtual `:any` remains unsupported.

ADR 0013 denies arbitrary package actions. The current CLI has a narrow, separate authenticated DSO profile path (ADR 0029): it reauthorizes each package, applies the compatibility gate, publishes bounded trees and switches a profile only after explicit confirmation. It never executes maintainer scripts or package binaries. General Debian package installation and service/kernel/system integration remain unsupported.

Downgrade regression tests use a caller-supplied fixture baseline and Debian version ordering. The metadata planner does not read an installed profile or host package database and does not yet enforce a profile upgrade/downgrade policy.

Local `dich inspect` reads bounded, unauthenticated `.deb` input and does not extract it; its report always marks the local archive unverified and non-installable. Authenticated `fetch --publish-tree` and `install` use separately verified repository artifacts and the private staging/publishing path. Unsupported archive formats, links, special files and tar extensions fail closed.

Archive validation rejects absolute and parent paths, normalized duplicates, file/directory collisions, dangerous mode bits and link/special/extension records. A Linux-only private staging API uses no-follow, beneath-root `openat2` operations; publication accepts only artifacts with a current signed metadata authorization and verified digest.

Staging rejects archive links and extension records rather than preserving them, writes files as 0600, and does not preserve ownership or xattrs. Its private temporary tree is not a same-UID isolation boundary. The store publisher rechecks artifact binding and file hashes during copying and fails closed if required containment primitives or a safe temporary root are unavailable.

Known maintainer scripts are reported only by name, size and SHA256, and trigger-file presence is recorded (ADR 0016). Their content is never executed or copied to the data staging tree. Script or trigger presence fails the DSO installation gate; trigger semantics and all package integration behavior are not emulated.

Store identity is derived from the authenticated artifact digest and source/snapshot context. Existing object bytes are verified during publication and by explicit store verification; equal package versions from different source snapshots are not treated as identical by version string alone. The host filesystem owner remains trusted and can modify its own files outside Dich's API.

The preliminary store metadata database (ADR 0018) requires an existing private, trusted directory, rejects symlink/hardlink database and lock files and special mode bits on protected paths, uses an exclusive advisory lock and configures SQLite WAL with synchronous FULL. The library can publish raw archives and conservative extracted trees on the same filesystem, but process-level failure tests do not prove power-loss durability. Same-UID adversaries, ambiguous unmarked initializations and network filesystems remain unresolved; partial markers have a narrowly scoped explicit recovery path.

The experimental store can persist a reauthenticated raw `.deb` with exclusive staging, file/directory fsync, no-replace rename, SQLite WAL/FULL metadata and byte comparison before reuse. The experimental tree publisher checks every file against its staged manifest, rejects unexpected entries and links, and rechecks stored contents on reuse. Explicit recovery can inventory or remove selected abandoned stages and unreferenced objects under the store lock; it checks current graph memberships but is not garbage collection, and must be updated before other reference types are introduced. Graph records describe dependencies, not verified contents or GC roots. Same-UID attackers and real power-loss behavior remain outside the demonstrated boundary. No CLI command activates these objects.

The experimental library tree verifier checks committed local identity and manifest data, every stored file hash, paths, permissions and unexpected entries; the archive verifier checks size and digest against the identity and stored bytes. It does not reauthenticate repository signatures, verify artifact freshness, establish runtime compatibility or provide hard immutability; protected metadata and the same-UID trust boundary still apply.

Stored tree files use mode 0400 and directories 0700; archives use 0400. This is a best-effort convention enforced by verification, not a kernel-enforced immutable store: the owning UID can change permissions or replace contents. Graphs and object records are not GC roots and do not authorize activation.

The experimental `store ls` output is metadata only and labels lifecycle as recorded rather than content verified. `store verify` checks one object against protected local metadata, not against a freshly verified repository snapshot or ABI policy. Both report compatibility as not analyzed and do not claim installability. Both require an existing current-schema store and an exclusive lock; SQLite may create or recover WAL sidecars. They do not initialize, migrate or activate a store.

`dich inspect FILE` treats the file as unauthenticated input, reads a bounded regular file without following symlinks, does not extract or execute package scripts, and does not claim installability. It rejects FIFO/device inputs and unsupported archive forms.

Experimental `fetch` requires an exact version, component, one configured source and explicit freshness policy. It reauthenticates cached signed Release/index metadata and checks the size and SHA256 of reused or downloaded bytes; a corrupt cached blob is an error rather than a silent network fallback. A live Ubuntu Noble update and exact artifact fetch were verified through an explicitly configured HTTP CONNECT proxy using the configured Ubuntu archive keyring. The test used an old signed snapshot with a deliberately broad test freshness age and missing-Valid-Until allowance; this is not a production freshness recommendation. Downloaded does not mean installable.

Network commands optionally accept an explicit unauthenticated HTTP CONNECT proxy URL. Dich ignores proxy environment variables, does not persist the proxy, keeps HTTPS certificate validation and repository signature checks enabled, and rejects proxy credentials and non-HTTP schemes. A proxy can observe destination metadata and deny or alter transport; an intercepting certificate not trusted by the application is rejected (ADR 0021).

The optional `fetch --publish-tree` revalidates authorization, stages only the supported archive subset and publishes a private tree. It does not run maintainer scripts, analyze compatibility or activate the package. Failure may leave a verified cache entry or recoverable store remnants.

The `dich-elf` library parses bounded single-object ELF bytes with pinned Goblin and reports structural loader and ABI evidence, including interpreter, NEEDED libraries, search paths, symbol versions, visible exports and direct dynamic-loader imports. `.deb` inspection binds this evidence to archive paths and reports heuristic paths, shebangs, text absolute-path tokens, and selected host/service command markers. Oversized or malformed ELF is rejected and no package bytes are executed. ELF facts do not establish general libc or ABI compatibility.

`.deb` inspection records bounded heuristic path and text indicators for configuration, service units, pkg-config/CMake, NSS/locale, shebangs, absolute path tokens and selected host commands (ADR 0023). Text scanning is not semantic analysis; false positives and false negatives are expected. Scripts remain metadata only, and no reported or absent indicator establishes safety.

`dich inspect --json` emits a versioned compatibility evidence report (ADR 0024). The archive remains unverified and `installable` remains false. `supported` is limited to the standalone DSO rule in ADR 0025 or a caller-supplied complete closure of simple DSOs in ADR 0027. Closure analysis rejects missing or ambiguous SONAMEs, cycles, unresolved or unreachable symbols, versioned imports/exports, loader search paths, constructors and integration markers. Debian Depends resolution, repository authentication for local inputs, publication and activation remain separate unsupported steps.

The closure runtime fixture preloads dependency DSOs in dependency-first order with glibc `dlmopen` in a fresh link-map namespace per version. `dlmopen` does not sandbox code or restrict syscalls; any loaded function executes with caller privileges and requires a trusted publisher. No binary patching, ambient loader path, host mount, installation or activation is performed.

Profile generations are SHA256-addressed manifests switched by relative symlink rename after fsyncs (ADR 0028). The CLI reads v1/v2 manifests and writes v3 package-labelled generations. `profile list` validates active pointers; `rollback` and `remove` are dry-runs until `--yes`. Removal retains a validated inactive pointer for rollback; no object is deleted. Install trusts only one configured signed source and reauthorizes every artifact against fresh Release/Packages metadata, then checks the entire archive closure against the strict DSO policy before publishing trees or switching the profile (ADR 0029). No maintainer script or package binary is executed. Returned DSO paths are explicit caller inputs; loading them executes code with caller privileges and is not sandboxed. Profile reads validate graph membership but do not rehash referenced tree bytes; use store verification separately.

Mark-and-sweep garbage collection operates under the store's exclusive advisory lock (`metadata.lock`), preventing concurrent mutation races (ADR 0030). Roots are collected by scanning active profiles (`current` symlinks) and traversing their complete `previous_id` generation chains, ensuring rollback targets are never collected. Any explicit pins or active leases also contribute roots. Inactive or removed profiles do not contribute roots, allowing their unreachable packages to be reclaimed. Shared dependency libraries (such as shared DSOs referenced by multiple profiles or generations) are preserved as long as at least one active generation references them. `dich gc` defaults to `--dry-run`, requiring explicit `--execute` to perform deletions. Tree deletions use descriptor-relative non-symlink traversal (`openat2` with `BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV`) with depth and entry bounds and directory fsync, followed by immediate SQLite metadata transactions. Missing objects on disk are reconciled safely without panicking.

## Phase 6 Security Review: Key Handling, Filesystem/TOCTOU, Paths, Privilege Model, and Container Limits

A structured security audit (ADR 0034) reviews and confirms the containment invariants across the system:

1. **Key Handling**:
   - Explicit `Signed-By` keyrings in source configuration; ambient host keyrings are rejected.
   - Keyrings opened via descriptor-relative traversal (`openat_nofollow_path`) with ownership and mode checks (root or user owned, no group/world write, no symlinks anywhere in path).
   - InRelease / Release.gpg verification mediated by `/usr/bin/gpgv` run in an isolated subprocess with synthetic temporary keyrings under `prlimit` constraints (address space, file size, CPU time, open file descriptors).
   - Signer fingerprints cryptographically verified against configured fingerprints; subkeys must bind to authorized primary fingerprints; revoked or expired keys fail closed; multi-signature validation requires all signers to be authorized.

2. **Filesystem and TOCTOU Attacks**:
   - Traversal uses descriptor-relative calls (`openat`, `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`).
   - Store and cache directories, metadata database, journal, WAL sidecars, and lock files strictly reject symlinks and hardlinks (`st_nlink > 1`).
   - Mutations use atomic temporary file creation (`O_EXCL`, 0600) and atomic renames (`renameat2` or `rename`) with directory fsync.
   - Staging operates within randomized private 0700 directories in `/tmp` using beneath-root constraints.

3. **Paths and Archive Containment**:
   - Package archives (.deb) are checked for directory traversal (`..`), absolute paths, NUL bytes, and control characters before staging.
   - Tar symlinks and hardlinks are rejected during staging and tree publication.
   - Committed store trees are content-addressed (`store/objects/trees/<sha256>`) and marked read-only (0400).

4. **Privilege Model**:
   - No background daemons, setuid binaries, or ambient capability escalations (ADR 0032).
   - Privilege boundary is process inheritance (sudo for system mode; XDG base directories for unprivileged rootless development).
   - Directory initialization enforces 0700 permissions with ownership checks; world-writable parent directories are rejected.
   - Maintainer scripts and triggers are never executed by default; host system packages and `/etc` remain untouched.

5. **Container Limits**:
   - Subprocesses constrained by `prlimit` against resource exhaustion.
   - Operations survive low `RLIMIT_NOFILE` limits without resource leakage.
   - Preflight disk space verification (`statvfs`) prevents partial writes.
   - Rootless `/tmp` permissions support user namespaces in Docker, Podman, and LXC containers.

