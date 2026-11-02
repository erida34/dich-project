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

The current `dich-apt` library can parse operator TOML policy from a bounded reader and import a restricted deb822 source under that independent policy (ADR 0002). The policy associates a declared distribution, exact URI and suite, allowed components, architecture, keyring path and full fingerprints. A separate gpgv prototype verifies signatures over supplied bytes against configured fingerprints, but callers must securely open the policy, source and keyring files; the CLI does not yet load them. Release identity and freshness, the integrity chain, and package operations are not implemented. Import or signature success alone is not evidence that a repository is safe to use.

## Invariants
- No store object is published prior to full verification.
- No version is activated without a fully validated dependency closure.
- No active object is deleted by GC.
- No automatic package script execution.
- Same physical object is reused only when its exact identity matches.
- A user-facing `install` success means profile-activated and behavior-tested for the supported package class, not merely extracted.
