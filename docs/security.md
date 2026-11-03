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

The deb822 importer applies an operator-supplied source allowlist, bounds input, and rejects unsupported fields, missing `Signed-By`, and nonmatching signing fingerprints. Policy TOML parsing rejects unknown fields. The CLI source listing opens policy and source files without following symlinks and rejects unsafe ownership or writable paths; listing does not authenticate a repository. Its URI syntax checks are not a network or redirect security policy. Authenticated update and offline metadata queries are implemented; installation and CLI artifact fetching are not.

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

The core action-admission boundary (ADR 0013) denies all package execution and store mutation, including when evidence is empty or unexamined. It enumerates prohibited action classes but does not yet inspect `.deb` contents; real script/trigger/service/kernel detection and trusted evidence binding remain future work. CLI mutation commands return unsupported before executing package data.

Downgrade regression tests use a caller-supplied fixture baseline and Debian version ordering. The metadata planner does not read an installed profile or host package database and does not yet enforce a profile upgrade/downgrade policy.

Experimental `.deb` inspection reads bounded common-ar/control/data tar streams, including gzip/xz/zstd through resource-limited helpers (ADR 0014); it performs no extraction, does not establish safe paths or links, and is not yet connected to trusted artifact fetch. It rejects extended records and non-regular/non-directory tar types. Other compression formats, links, special files and tar extensions remain unsupported; safe extraction is not implemented.
