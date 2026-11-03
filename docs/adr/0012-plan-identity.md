# ADR 0012 — Informational plan identity

Status: Accepted for metadata plans; persistent locks and execution remain unimplemented.

Each selected package in the versioned JSON `pins` array includes its exact name and version, package architecture, distribution, literal suite, component, repository URI, source architecture, configured fingerprint allowlist, path, size, artifact SHA256, and SHA256 of the authenticated Release plaintext. The Release digest identifies the signed snapshot content, not the signature envelope; fingerprints are configured trust constraints, not a claim about which signer produced a particular signature. Each artifact entry is extracted from an index authenticated by that Release and is rejected when missing, ambiguous, malformed or outside the artifact path policy. The cache and Release are rechecked during plan construction. Human output includes package, source, suite and both digests; JSON carries the full identity.

A plan is informational and has no durable lock-file reader, replay or fetch/install authority. Data may expire or change after output; future consumers must independently reauthenticate the snapshot and verify all pins and artifact bytes, as well as compatibility and transaction policy. The single-source and resource limitations of ADR 0011 remain in force.
