# Store Database Format, Migration, Durability, and Backup/Restore Guide

## 1. Store Database Architecture

Dich's durable metadata is stored in SQLite at `<store-dir>/metadata.sqlite3` alongside `<store-dir>/metadata.lock` and the initialization marker `<store-dir>/.dich_initialized`.

### Database Header and Schema Invariants
- **Application ID**: `0x44494348` (decimal `1145652040`, ASCII "DICH"). Any database lacking this application ID is rejected as unknown.
- **Journal Mode**: Write-Ahead Logging (`WAL`), ensuring concurrency safety and fast reads.
- **Synchronization**: `FULL` (`PRAGMA synchronous = FULL`), guaranteeing that committed transactions survive operating system crashes.
- **Foreign Key Constraints**: Enforced (`PRAGMA foreign_keys = ON`).

### Schema Evolution and Versions

| Schema Version | Introduced Tables | Purpose |
|---|---|---|
| **v1** | `publication_intents` | Tracks in-flight staging directories during atomic publication. |
| **v2** | `verified_archives` | Content-addressed storage for verified `.deb` raw archive blobs. |
| **v3** | `verified_trees` | Content-addressed storage for verified unpacked package file trees. |
| **v4** | `reference_graphs`, `reference_members` | Directed dependency reference graphs and profile generation edges. |

---

## 2. Migration and Downgrade Policy

### Forward Migration
When a newer version of Dich opens an existing store database:
1. Dich verifies that the database has application ID `0x44494348`.
2. Dich checks the current `PRAGMA user_version`.
3. If `user_version < CURRENT_VERSION`, migrations execute sequentially in transactional batches (`migrate_to_v2`, `migrate_to_v3`, `migrate_to_v4`).
4. If any migration step fails, the transaction rolls back cleanly, leaving the database at its previous schema version.

### Downgrade Protection (Fail-Closed)
- Running an older Dich executable against a newer database schema version (`database user_version > supported version`) fails closed with `MetadataError::UnknownSchema`.
- Dich **never** attempts to silently modify, delete, or downgrade schema tables it does not recognize.
- Operators must use the corresponding or newer Dich binary.

---

## 3. Crash Consistency and Recovery

Dich employs a multi-layered crash recovery design:

1. **Advisory File Lock (`metadata.lock`)**:
   - Held exclusively for the entire duration of any mutating transaction.
   - Prevents race conditions from concurrent processes.
2. **Initialization Recovery**:
   - If store initialization is interrupted before `.dich_initialized` is committed, `recover_empty_initialization` cleans up partial database files only if no objects have been committed.
3. **Sidecar Link Validation**:
   - Database sidecars (`metadata.sqlite3-wal`, `metadata.sqlite3-shm`, `metadata.sqlite3-journal`) are inspected via descriptor-relative `fstat`. Any symlinked or hardlinked sidecar is rejected immediately (`MetadataError::UnsafePath`), preventing link-swap attacks.
4. **Staging Recovery**:
   - `dich store ls` and `dich gc` automatically inventory abandoned staging directories. In-flight publication failures never commit partial objects into `verified_trees`.

---

## 4. Backup and Restore Procedures

### Safe Backup Methods

Because SQLite in WAL mode writes changes to `metadata.sqlite3` and `metadata.sqlite3-wal`, copying files while writers are active without locking can produce an inconsistent database snapshot.

#### Method A: Offline Filesystem Backup (Recommended)
When no Dich processes are active:
1. Ensure no process holds `metadata.lock`:
   ```sh
   fuser <store-dir>/metadata.lock
   ```
2. Archive the complete store directory:
   ```sh
   tar -C <store-dir> -cf dich-backup.tar .
   ```

#### Method B: Online SQLite Backup
If Dich processes may be reading:
```sh
sqlite3 <store-dir>/metadata.sqlite3 ".backup <backup-dir>/metadata.sqlite3"
cp -a <store-dir>/objects <backup-dir>/
cp -a <store-dir>/profiles <backup-dir>/
cp -a <store-dir>/.dich_initialized <backup-dir>/
touch <backup-dir>/metadata.lock
```

### Restore Procedure

1. Recreate the store directory with private mode 0700:
   ```sh
   mkdir -p <target-store-dir>
   chmod 0700 <target-store-dir>
   ```
2. Restore files from the backup archive:
   ```sh
   tar -C <target-store-dir> -xf dich-backup.tar
   ```
3. Ensure file permissions:
   ```sh
   # Database and lock files must be 0600
   chmod 0600 <target-store-dir>/metadata.sqlite3* <target-store-dir>/metadata.lock
   # Stored tree objects must be read-only 0400
   find <target-store-dir>/objects -type f -exec chmod 0400 {} +
   find <target-store-dir>/objects -type d -exec chmod 0700 {} +
   ```
4. Verify integrity of restored objects:
   ```sh
   dich --store-dir <target-store-dir> store ls
   # Check individual objects against recorded SHA-256 manifests
   dich --store-dir <target-store-dir> store verify <object_id> --kind tree
   ```
5. Confirm active profiles:
   ```sh
   dich --store-dir <target-store-dir> profile list
   ```
