# ADR 0028 — Profile generations and current pointer

Status: Accepted for the first non-installing profile metadata slice.

## Data model

Each profile is a private directory at `profiles/<name>/`. It contains immutable canonical manifest files under `generations/<generation-id>` and one relative `current` symlink to `generations/<generation-id>`. The manifest identifies the profile, the canonical reference-graph digest and its immutable object IDs/edges. Its generation ID is SHA256 over the canonical manifest. The existing `ReferenceGraph` and committed tree metadata are the source of object membership; profile APIs must reject uncommitted or corrupt references.

Profile names are bounded lowercase ASCII identifiers. The profile root, generations, manifest and pointer are accessed relative to already-open protected directory handles without following caller-controlled links. The manifest is mode 0400 after publication. Generation directories are retained; deletion and GC are separate milestones.

## Publication order

Under the existing exclusive store lock: validate the graph; write a uniquely named temporary manifest; fsync it; rename it without replacement to its content-derived generation ID and fsync `generations`; create a temporary relative symlink; atomically rename it over `current`; fsync the profile directory. A failure before the pointer rename leaves the old generation current. A crash after generation publication but before switching may leave a harmless unreferenced manifest. The symlink is the authoritative active-generation pointer; SQLite does not mirror profile state, avoiding a false cross-filesystem/database atomicity claim.

The first slice provides library APIs to publish/read/list generations. Tests verify manifest identity, immutable file mode, graph membership, idempotent reuse, switching while retaining the prior generation, unsafe names and pointer-escape rejection. It does not install files, activate executables, execute scripts, remove packages, or claim physical power-loss proof. Process-level failure injection and cross-boot durability remain later gates.
