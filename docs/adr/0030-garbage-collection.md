# ADR 0030 — Mark-and-sweep garbage collection

Status: Accepted for store-level mark-and-sweep garbage collection of unreachable objects.

## Context

Dich stores verified immutable package tree objects and canonical reference graphs in `objects/` and SQLite metadata. Profile generations in `profiles/<name>/` select reference graphs and form chains through `previous_id`. When packages or profiles are upgraded, replaced, or removed, older unreferenced trees and graphs may remain in the store. Without garbage collection, disk usage grows monotonically.

## Decision

Implement mark-and-sweep garbage collection under the exclusive store lock (`.lock`).

### Roots
Roots are identified by scanning all profiles in `profiles/`:
- For every profile with an active relative `current` symlink, read the generation manifest and traverse its `previous_id` chain.
- For each reachable generation, its `graph_id` is marked reachable, and every node in its canonical `ReferenceGraph` (a verified tree object ID) is marked reachable.
- Profiles that have been deactivated or removed (i.e. lacking a `current` pointer) do not contribute roots; their unreachable objects are eligible for collection unless referenced by an active profile.
- Any object reachable from at least one active profile root is preserved. Shared dependency libraries used by multiple profiles or generations remain preserved as long as at least one active generation references them.

### Mark and Sweep
1. **Mark**: Form `reachable_trees` and `reachable_graphs` from the root set.
2. **Sweep**: Enumerate stored objects from `verified_trees` in SQLite and filesystem `objects/`.
   - Any tree whose ID is not in `reachable_trees` is marked unreachable.
   - Any reference graph not in `reachable_graphs` is marked unreachable.
3. **Execution Modes**:
   - `dry-run` (default): inspects roots and unreachable objects, reports counts and reclaimable bytes, and performs zero mutations.
   - `execute` (`--execute`): requires explicit opt-in. Under the exclusive store lock, safely deletes unreachable trees from `objects/` using descriptor-relative, non-symlink traversal, unlinks directories with fsync, and deletes metadata rows from `verified_trees`, `reference_members`, and `reference_graphs`.

### CLI Contract
- `dich gc [--dry-run]` (default): outputs planned removals, itemized unreachable objects, and reclaimable bytes.
- `dich gc --execute`: executes deletions and outputs completed status, freed bytes, and retained object counts.
- `--json`: outputs versioned machine-readable JSON reports.

## Verification
- Unit and store tests verify:
  - Reachability analysis marks all active profile graph nodes.
  - Deletion removes only unreachable trees and graphs while preserving active objects.
  - Dry-run performs no deletions or mutations.
  - Deleting an unreferenced tree updates filesystem and SQLite consistently.
- End-to-end integration tests verify:
  - Installing A/B variants sharing a common dependency.
  - Deactivating one profile.
  - GC removes only the unreachable variant and preserves the shared library.
  - Rollback on the active profile remains functional and loads the shared library via `dlmopen`.
