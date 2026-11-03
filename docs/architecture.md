# Dich architecture

## North star
Original signed apt repositories -> verified metadata/artifacts -> deterministic solver -> safe extraction -> relocation/ABI report -> immutable shared store -> atomic activation profiles -> GC.

## Separation of concerns
1. Repository source is identified by origin, suite, components, architecture and trusted signing keys. It is not a general web scraper.
2. Package identity: name, Debian version including epoch/revision, architecture, origin, index digest, `.deb` digest and extraction/relocation policy. An identical version string from different repositories is NOT automatically identical content.
3. Store identity: hash of normalized verified payload plus relevant transformation policy/inputs (exact formula specified in an ADR before implementation). Store references are explicit; logical packages and physical objects are distinct concepts.
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
/var/lib/dich/profiles/<name>/        generation manifests/symlinks
/var/log/dich/                        only if file logging explicitly enabled
```

XDG/user store support will be an independently specified mode. Never use arbitrary user-controlled file paths for privileged extraction. `dich` itself is packaged as `/usr/bin/dich`, distinct from its managed store.

## Trust boundary
APT authenticity -> verified Release -> hash-verified Packages -> hash-verified `.deb`. Signature verification alone does not grant permission to execute package scripts or to modify system files. Relocation transforms package bytes, creating a new store object identity.

The source policy binds distribution, URI, suite, components, architecture, keyring and fingerprints (ADR 0002). Protected file loading and configured-keyring `gpgv` verification establish the input boundary (ADRs 0003 and 0008). Source listing reports configuration only.

`update` verifies InRelease or, only on HTTP 404, detached Release and Release.gpg, checks origin, suite and explicit freshness policy, then fetches and verifies each signed Packages index (ADRs 0004 and 0008). A protected cache maintains a per-source rollback floor and reauthenticates cached metadata on read (ADR 0007). Individual cache entries are durably published, but an update across entries or sources is not atomic: failure may leave a partial cache. Offline queries fail closed on missing or inconsistent indices, and do not provide a global concurrent snapshot.

Control and Debian version parsers support cached package name/version queries, but do not solve dependencies or establish compatibility (ADR 0005). A relationship model preserves Depends, Pre-Depends, Conflicts, Breaks, Provides, Multi-Arch and essential/required markers without solving them (ADR 0010). A core policy model and signed Release adapter enforce exact distribution, suite and architecture identity when called (ADR 0009); the experimental single-source metadata planner applies that boundary, but the resolver is incomplete and does not authorize installation (ADR 0011). Informational plans include signed Release and artifact identities but cannot be replayed as locks (ADR 0012). Verified artifacts can be downloaded through library APIs under the signed index and restricted HTTPS policy (ADR 0006); the CLI cannot fetch or install them. These features require a trusted clock and protected local storage. Import or signature success alone is not permission to execute package scripts or modify system files.

## Invariants
- No store object is published prior to full verification.
- No version is activated without a fully validated dependency closure.
- No active object is deleted by GC.
- No automatic package script execution.
- Same physical object is reused only when its exact identity matches.
- A user-facing `install` success means profile-activated and behavior-tested for the supported package class, not merely extracted.
