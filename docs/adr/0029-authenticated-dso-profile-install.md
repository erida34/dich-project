# ADR 0029 — Authenticated DSO profile installation

Status: Accepted for authenticated single-root DSO profile selection.

## Decision

`dich install` may select one requested package and its complete resolver-selected dependency set into a named profile only when every artifact is fetched from exactly one configured source, reauthorized against fresh signed Release and Packages metadata, and the complete set passes ADR 0027's x86-64 glibc DSO closure policy. `--exact-version` constrains the requested root using Debian version semantics; otherwise the resolver's normal candidate policy applies. The CLI requires `--yes` before network artifact fetch, extraction, store publication or profile switching. Without it, the command prints an informational metadata plan. Unsupported scripts, triggers, non-DSO payloads, missing or ambiguous dependencies, other architectures, multiple configured sources and closure-limit overflows fail closed.

The store keeps the original ELF bytes in verified private tree objects. Profile manifests identify the requested root package and the committed object graph. Output gives the explicit object paths and dependency-first SONAME order required by a caller using a fresh glibc `dlmopen` namespace. Dich does not load package code, rewrite ELF, alter loader paths or environment, create a root filesystem, run package executables, or claim a sandbox. Any caller that later loads the DSO executes publisher-controlled code with that caller's privileges.

A profile selects one requested root and its resolver-selected object set. Replacing that root creates a new generation whose parent is available for rollback; a different requested root must use a different profile. `remove --yes` atomically moves the current pointer to a validated inactive pointer; it retains manifests and objects so a prior generation can be restored. There is no object deletion or garbage collection in this slice.

Tree objects are published individually before the profile pointer changes. A failure can leave committed but unreferenced trees; the old profile remains selected until the final pointer switch. Group publication recovery and fault injection are a later transaction milestone.

## Limits

The resolver plan currently supplies package membership but not a durable package-to-package edge map; the stored graph records all selected objects as roots. Consequently this release cannot safely remove one package from a multi-root profile, and profiles intentionally have one requested root. Profile reads validate graph membership but do not rehash object bytes; `dich store verify` remains a separate check. Cross-source resolution, persistent lock replay, multi-package profile composition, `dich run`, ELF activation and DSO loading remain unsupported.

## Verification

Fixture-first CLI coverage uses a generated signing key and signed repository metadata, two exact versions of an authenticated local `.deb` containing a self-contained test DSO, and a separate scripted non-DSO package that must be rejected. It verifies plan-only behavior, selection of both versions, distinct profile generations, rollback through the CLI, and retained object bytes. The fixture does not establish trust in any public repository, arbitrary package compatibility, loading the signed installed path in `dlmopen`, sandboxing, or production power-loss behavior.
