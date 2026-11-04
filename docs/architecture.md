# Dich architecture

## North star
Original signed apt repositories -> verified metadata/artifacts -> deterministic solver -> safe extraction -> relocation/ABI report -> immutable shared store -> atomic activation profiles -> GC.

## Separation of concerns
1. Repository source is identified by origin, suite, components, architecture and trusted signing keys. It is not a general web scraper.
2. Package identity: name, Debian version including epoch/revision, architecture, origin, index digest, `.deb` digest and extraction/relocation policy. An identical version string from different repositories is NOT automatically identical content.
3. Store identity v1 hashes the verified artifact digest plus exact source/snapshot context and transformation policy (ADR 0017); actual stored bytes must be verified separately. Store references are explicit; logical packages and physical objects are distinct concepts.
4. Resolution: Debian dependency relations, alternatives, virtual packages and conflicts; never infer ABI compatibility from package metadata alone.
5. Compatibility: separately characterize data-only, library-only, executables, services/system packages; narrow allowed subset first.
6. Store transaction: download/stage -> validate -> durable publish -> update SQLite metadata -> profile switch. Crash recovery must avoid DB/filesystem divergence.
7. GC roots: active and rollback profile generations, pins, active leases; cross-process locking is required.
8. Human command UX and JSON schema must have stable error types and exit codes.

## Proposed filesystem

```text
/etc/dich/config.toml                 system configuration (not modified silently)
/var/lib/dich/state.sqlite           metadata DB (once initialized)
/var/cache/dich/                      verified metadata/blob cache
/var/lib/dich/store/<identity>/       immutable objects (provisional path)
/var/lib/dich/profiles/<name>/        generations/<sha256> manifests; current -> generations/<sha256>
/var/log/dich/                        only if file logging explicitly enabled
```

XDG/user store support will be an independently specified mode. Never use arbitrary user-controlled file paths for privileged extraction. `dich` itself is packaged as `/usr/bin/dich`, distinct from its managed store.

## Trust boundary
APT authenticity -> verified Release -> hash-verified Packages -> hash-verified `.deb`. Signature verification alone does not grant permission to execute package scripts or to modify system files. Relocation transforms package bytes, creating a new store object identity.

The source policy binds distribution, URI, suite, components, architecture, keyring and fingerprints (ADR 0002). Protected file loading and configured-keyring `gpgv` verification establish the input boundary (ADRs 0003 and 0008). Source listing reports configuration only.

`update` verifies InRelease or, only on HTTP 404, detached Release and Release.gpg, checks origin, suite and explicit freshness policy, then fetches and verifies each signed Packages index (ADRs 0004 and 0008). A protected cache maintains a per-source rollback floor and reauthenticates cached metadata on read (ADR 0007). Individual cache entries are durably published, but an update across entries or sources is not atomic: failure may leave a partial cache. Offline queries fail closed on missing or inconsistent indices, and do not provide a global concurrent snapshot.

CLI freshness defaults to a 24-hour maximum age. Signed `Valid-Until` is enforced when present; if absent, the signed `Date` remains bounded by the same maximum age. `--require-valid-until` opts into rejecting metadata without that field (ADR 0042).

Control and Debian version parsers support cached package queries, but do not establish compatibility (ADR 0005). Relationship models preserve dependency metadata (ADR 0010); the experimental planner enforces a release/architecture policy but does not produce replayable locks (ADRs 0009, 0011 and 0012). The CLI can fetch exact artifacts and publish extracted trees (ADRs 0006 and 0020). A separate engine may select only authenticated DSO closures into metadata profiles (ADR 0029). The `dich-deb` library stages verified cached artifacts privately (ADRs 0014 and 0015). The SQLite WAL store publishes raw archives and private trees with fsync and no-replace rename; cleanup is explicit (ADR 0018). Package code is not executed by install/remove and maintainer scripts remain metadata only (ADR 0016). These features require a trusted clock and protected local storage. Import or signature success alone is not permission to execute package scripts or modify system files.

`dich-elf` exposes bounded single-object ELF evidence through the pinned Goblin parser: interpreter, SONAME, NEEDED, RPATH/RUNPATH, required symbol versions and direct dynamic-loader imports (ADR 0022). The `.deb` inspector binds those reports to archive paths and records heuristic configuration/service/pkg-config/CMake/NSS/locale paths, text absolute-path tokens, shebangs, maintainer triggers and selected service/host command markers (ADR 0023). Evidence is incomplete and does not approve ABI compatibility or relocation.

`dich inspect --json` maps these findings to a versioned `compatibility_report` with conservative states. Without `--with`, `supported` includes the standalone DSO class in ADR 0025. Repeated `--with DEB` arguments provide an explicit local DSO closure for ADR 0027; analysis checks unique SONAMEs, internal DT_NEEDED edges, dependency reachability for imported symbols, collisions and dependency-first load order. Local inputs remain untrusted and non-installable. `dich install` separately authenticates every selected archive and selects the DSO closure in a named metadata profile; it returns explicit paths and does not load them (ADR 0029).

No general relocation strategy is selected. RUNPATH patching, wrappers and host mount namespaces remain deferred. The dependency closure fixture uses glibc `dlmopen` in a fresh link-map namespace, loading each DSO by explicit path and in the reported dependency-first order. This namespace isolates symbol lookup only; it is not a process or privilege sandbox and is limited to the tested x86-64 glibc runtimes (ADRs 0026 and 0027).

Profile manifests preserve the validated graph identity, parent generation, and (in v3) requested root package label. The install boundary is one authenticated source and the complete ADR 0027 DSO closure; it stages and selects unchanged trees, then reports explicit object paths and dependency-first load order. No code is executed or host loader state changed. Each profile has one requested root; replacing it creates a rollback generation. `remove --yes` moves the active pointer to an inactive retained pointer, and rollback can select the previous generation. Objects remain stored, graph edges are not yet reconstructed from resolver dependencies, and GC/recovery are incomplete (ADRs 0028 and 0029).

## Invariants
- No store object is published prior to full verification.
- No version is activated without a fully validated dependency closure.
- No active object is deleted by GC.
- No automatic package script execution.
- Same physical object is reused only when its exact identity matches.
- A user-facing `install` success means profile-activated and behavior-tested for the supported package class, not merely extracted.
