# ADR 0039 — Store Database Migration, Downgrade Protection, Durability, and Backup

Status: Accepted for Phase 7 public release.

## Context

Dich relies on SQLite to track immutable store objects, dependency reference graphs, profile generations, and garbage collection roots. Operational reliability requires formal documentation of database schema migrations, downgrade prevention, failure recovery semantics, and backup/restore workflows.

The project roadmap requires:
> Document migration of store DB format, downgrade and recoverability, data durability and backup/restore.

## Decision

### 1. Database Identification and Schema Evolution
- The SQLite database `<store-dir>/metadata.sqlite3` uses explicit application identification `PRAGMA application_id = 0x44494348` and tracks schema versions through `PRAGMA user_version` (currently schema v4).
- Forward migrations execute in immediate transactions (`migrate_to_v2`, `migrate_to_v3`, `migrate_to_v4`). Failure at any step aborts and rolls back to preserve existing state.

### 2. Downgrade Policy
- Running an older binary against a newer schema (`user_version > CURRENT`) fails closed with `MetadataError::UnknownSchema`.
- Older binaries never attempt to execute migrations, drop unrecognized tables, or alter unknown structures.

### 3. Durability Guarantees
- Metadata transactions use `PRAGMA journal_mode = WAL` and `PRAGMA synchronous = FULL`.
- Mutations are serialized across processes via exclusive non-blocking advisory file lock on `<store-dir>/metadata.lock`.
- Stored tree objects are written with mode `0400` in `<store-dir>/objects/`, preventing accidental in-place mutation. Directories use `0700`.
- Directory `fsync` barriers are enforced before and after atomic `renameat2(RENAME_NOREPLACE)` operations.

### 4. Operational Recovery and Backup
- Comprehensive backup and restore procedures are established in `docs/store-migration-durability-and-backup.md`.
- Restoration requires validating file permissions and running `dich store verify` to ensure bit-level correspondence between stored objects and database manifests.

## Consequences

- Store schema evolution and downgrade behaviors are documented and predictable.
- Operators have tested procedures for database backup, snapshotting, and disaster recovery.
