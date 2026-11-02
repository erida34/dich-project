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

## Security review gate
No general `.deb` install support until there is a documented threat model, independent review of extraction/activation/GC paths, test corpus with hostile inputs, and crash/failure injection tests.
