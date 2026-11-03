# ADR 0015 — Extraction safety boundary

Status: Proposed; implementation in progress.

Extraction must occur only after trusted artifact verification, into a private staging directory through no-follow directory-relative filesystem operations. Archive inspection alone cannot authorize extraction or installation. Until symlink, hardlink, special-file, mode-bit and filesystem race policies are proven, reject links, special files, setuid/setgid/sticky modes, unknown extension/xattr records and unsafe or ambiguous paths. Reject absolute paths, parent components, duplicate normalized names and file/directory collisions. Do not preserve archive ownership or execute scripts. A future extractor must validate its destination, handle hostile concurrent changes without escaping the staging root, enforce resource limits, and test cleanup and failures. This ADR does not claim that an extractor currently exists.

Read-only archive inspection now rejects absolute and parent paths, duplicate normalized paths, file/directory collisions, unsafe mode bits, links, special files and extension records. This is preliminary validation only: no filesystem extraction, destination confinement, concurrent-race protection or trusted artifact binding has been implemented.
