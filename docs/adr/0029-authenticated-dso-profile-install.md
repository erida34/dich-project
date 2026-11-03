# ADR 0029 — Authenticated DSO profile installation

Status: Accepted for authenticated single-root DSO profile selection.

## Decision

`dich install` may select one requested package and its complete resolver-selected dependency set into a named profile only when every artifact is fetched from exactly one configured source, reauthorized against fresh signed Release and Packages metadata, and the complete set passes ADR 0027's x86-64 glibc DSO closure policy. `--exact-version` constrains the requested root using Debian version semantics; otherwise the resolver's normal candidate policy applies. The CLI requires `--yes` before network artifact fetch, extraction, store publication or profile switching. Without it, the command prints an informational metadata plan. Unsupported scripts, triggers, non-DSO payloads, missing or ambiguous dependencies, other architectures, multiple configured sources and closure-limit overflows fail closed.

The store keeps the original ELF bytes in verified private tree objects. Profile manifests identify the requested root package and the committed object graph. Output gives the explicit object paths and dependency-first SONAME order required by a caller using a fresh glibc `dlmopen` namespace. Dich does not load package code, rewrite ELF, alter loader paths or environment, create a root filesystem, run package executables, or claim a sandbox. Any caller that later loads the DSO executes publisher-controlled code with that caller's privileges.

A profile selects one requested root and its resolver-selected object set. Replacing that root creates a new generation whose parent is available for rollback; a different requested root must use a different profile. `remove --yes` atomically moves the current pointer to a validated inactive pointer; it retains manifests and objects so a prior generation can be restored. There is no object deletion or garbage collection in this slice.

Tree objects are published individually before the profile pointer changes. A failure can leave committed but unreferenced trees; the old profile remains selected until the final pointer switch. Group publication recovery and fault injection are a later transaction milestone.

## Limits

The resolver plan determines one root package and derives exact directed dependency edges across the closure; the stored `ReferenceGraph` records the requested root and directed dependency edges to referenced tree objects. Multi-root profile composition (arbitrary independent package roots combined in one profile) remains unsupported; profiles select one requested root package and its closure. Profile reads validate graph membership but do not rehash object bytes; `dich store verify` remains a separate check. Cross-source resolution, persistent lock replay, `dich run`, and general ELF activation remain unsupported.

## Verification

Fixture-first CLI coverage uses a generated signing key and signed repository metadata, self-contained and multi-package dependency closure packages (`dich-plugin` depending on `libdich-common`), and a separate scripted non-DSO package that is rejected. It verifies plan-only behavior, selection of multiple versions, distinct profile generations, shared dependency tree reuse across generations, rollback through the CLI, and retained object bytes. Runtime loading of the installed signed paths is verified through `dlmopen-checker` in an isolated glibc link-map namespace. The fixture does not establish trust in any public repository, arbitrary package compatibility, sandboxing, or production power-loss behavior.
