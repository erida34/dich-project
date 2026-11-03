//! SQLite metadata foundation. No object publication is implemented here.
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use rustix::{
    fs::{self, CWD, FileType, Mode, OFlags},
    process::geteuid,
};
use std::{
    error::Error,
    fmt,
    os::fd::OwnedFd,
    path::{Component, Path},
    time::Duration,
};

const APPLICATION_ID: i64 = 0x4449_4348;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataError {
    UnsafePath,
    Sqlite,
    UnknownSchema,
    Busy,
    Io,
}
impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store metadata failed: {self:?}")
    }
}
impl Error for MetadataError {}

/// Protected SQLite connection; it does not yet publish or reference objects.
pub struct MetadataDb {
    // Fields drop in declaration order: SQLite must close before the advisory lock is released.
    pub(crate) connection: Connection,
    _file: OwnedFd,
    pub(crate) root: OwnedFd,
    _lock: OwnedFd,
}
impl MetadataDb {
    pub fn open(path: &Path) -> Result<Self, MetadataError> {
        let root = open_private_directory(path)?;
        let lock = acquire_lock(&root)?;
        for name in [
            "metadata.sqlite3-wal",
            "metadata.sqlite3-shm",
            "metadata.sqlite3-journal",
        ] {
            check_sidecar(&root, name)?;
        }
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let (file, created) = match fs::openat(
            &root,
            "metadata.sqlite3",
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(file) => (file, true),
            Err(rustix::io::Errno::EXIST) => (
                fs::openat(&root, "metadata.sqlite3", flags, Mode::empty())
                    .map_err(|_| MetadataError::UnsafePath)?,
                false,
            ),
            Err(_) => return Err(MetadataError::UnsafePath),
        };
        check_file(&file)?;
        let file_stat = fs::fstat(&file).map_err(|_| MetadataError::Io)?;
        let db_path = path.join("metadata.sqlite3");
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection =
            Connection::open_with_flags(db_path, flags).map_err(|_| MetadataError::Sqlite)?;
        let after = fs::openat(
            &root,
            "metadata.sqlite3",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| MetadataError::UnsafePath)?;
        check_file(&after)?;
        let after_stat = fs::fstat(&after).map_err(|_| MetadataError::Io)?;
        if file_stat.st_dev != after_stat.st_dev || file_stat.st_ino != after_stat.st_ino {
            return Err(MetadataError::UnsafePath);
        }
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| MetadataError::Sqlite)?;
        let app: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(|_| MetadataError::Sqlite)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| MetadataError::Sqlite)?;
        let empty: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| MetadataError::Sqlite)?;
        if !((created && app == 0 && version == 0 && empty == 0)
            || (app == APPLICATION_ID && matches!(version, 1 | 2)))
        {
            return Err(MetadataError::UnknownSchema);
        }
        if app == APPLICATION_ID {
            let sql: String = connection.query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'publication_intents'", [], |row| row.get(0)).map_err(|_| MetadataError::UnknownSchema)?;
            if empty != version
                || sql
                    != "CREATE TABLE publication_intents (object_id TEXT PRIMARY KEY NOT NULL, stage_name TEXT NOT NULL, created_at INTEGER NOT NULL)"
            {
                return Err(MetadataError::UnknownSchema);
            }
        }
        if app == APPLICATION_ID && version == 2 {
            let sql: String = connection.query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'verified_archives'", [], |row| row.get(0)).map_err(|_| MetadataError::UnknownSchema)?;
            if sql
                != "CREATE TABLE verified_archives (object_id TEXT PRIMARY KEY NOT NULL, manifest BLOB NOT NULL, artifact_size INTEGER NOT NULL, artifact_sha256 BLOB NOT NULL)"
            {
                return Err(MetadataError::UnknownSchema);
            }
        }
        let mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|_| MetadataError::Sqlite)?;
        if !mode.eq_ignore_ascii_case("wal") {
            let selected: String = connection
                .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
                .map_err(|_| MetadataError::Sqlite)?;
            if !selected.eq_ignore_ascii_case("wal") {
                return Err(MetadataError::Sqlite);
            }
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| MetadataError::Sqlite)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| MetadataError::Sqlite)?;
        connection
            .pragma_update(None, "trusted_schema", "OFF")
            .map_err(|_| MetadataError::Sqlite)?;
        if app == 0 {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| MetadataError::Sqlite)?;
            transaction.execute_batch("CREATE TABLE publication_intents (object_id TEXT PRIMARY KEY NOT NULL, stage_name TEXT NOT NULL, created_at INTEGER NOT NULL); PRAGMA application_id = 1145652040; PRAGMA user_version = 1;").map_err(|_| MetadataError::Sqlite)?;
            transaction.commit().map_err(|_| MetadataError::Sqlite)?;
        }
        if version < 2 {
            migrate_to_v2(&mut connection, false)?;
        }
        for name in [
            "metadata.sqlite3-wal",
            "metadata.sqlite3-shm",
            "metadata.sqlite3-journal",
        ] {
            check_sidecar(&root, name)?;
        }
        fs::fsync(&root).map_err(|_| MetadataError::Io)?;
        Ok(Self {
            root,
            _file: file,
            _lock: lock,
            connection,
        })
    }
    #[cfg(test)]
    pub(crate) fn test_object_count(&self) -> i64 {
        self.connection
            .query_row("SELECT count(*) FROM verified_archives", [], |row| {
                row.get(0)
            })
            .unwrap()
    }
    pub fn journal_mode(&self) -> Result<String, MetadataError> {
        self.connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|_| MetadataError::Sqlite)
    }
    pub fn synchronous(&self) -> Result<i64, MetadataError> {
        self.connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(|_| MetadataError::Sqlite)
    }
    pub fn schema_version(&self) -> Result<i64, MetadataError> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| MetadataError::Sqlite)
    }
}
fn migrate_to_v2(connection: &mut Connection, inject_failure: bool) -> Result<(), MetadataError> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| MetadataError::Sqlite)?;
    tx.execute_batch("CREATE TABLE verified_archives (object_id TEXT PRIMARY KEY NOT NULL, manifest BLOB NOT NULL, artifact_size INTEGER NOT NULL, artifact_sha256 BLOB NOT NULL); PRAGMA user_version = 2;").map_err(|_| MetadataError::Sqlite)?;
    if inject_failure {
        return Err(MetadataError::Io);
    }
    tx.commit().map_err(|_| MetadataError::Sqlite)
}

fn acquire_lock(root: &OwnedFd) -> Result<OwnedFd, MetadataError> {
    let lock = fs::openat(
        root,
        "metadata.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| MetadataError::UnsafePath)?;
    check_file(&lock)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    loop {
        match fs::flock(&lock, fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(lock),
            Err(rustix::io::Errno::AGAIN) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(rustix::io::Errno::AGAIN) => return Err(MetadataError::Busy),
            Err(_) => return Err(MetadataError::Io),
        }
    }
}

fn open_private_directory(path: &Path) -> Result<OwnedFd, MetadataError> {
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(MetadataError::UnsafePath);
    }
    let mut root = fs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| MetadataError::UnsafePath)?;
    check_dir(&root, false)?;
    let components: Vec<_> = parts.collect();
    if components.is_empty() {
        return Err(MetadataError::UnsafePath);
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(MetadataError::UnsafePath);
        };
        root = fs::openat(
            &root,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| MetadataError::UnsafePath)?;
        check_dir(&root, index + 1 == components.len())?;
    }
    Ok(root)
}
fn check_dir(fd: &impl std::os::fd::AsFd, private: bool) -> Result<(), MetadataError> {
    let stat = fs::fstat(fd).map_err(|_| MetadataError::UnsafePath)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || stat.st_mode & if private { 0o077 } else { 0o022 } != 0
    {
        return Err(MetadataError::UnsafePath);
    }
    Ok(())
}
fn check_file(fd: &impl std::os::fd::AsFd) -> Result<(), MetadataError> {
    let stat = fs::fstat(fd).map_err(|_| MetadataError::UnsafePath)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > 64 * 1024 * 1024
    {
        return Err(MetadataError::UnsafePath);
    }
    Ok(())
}
fn check_sidecar(root: &OwnedFd, name: &str) -> Result<(), MetadataError> {
    match fs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => check_file(&fd),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(_) => Err(MetadataError::UnsafePath),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn transaction_failure_rolls_back_and_commit_survives_reopen() {
        let root = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut db = MetadataDb::open(root.path()).unwrap();
        {
            let tx = db.connection.transaction().unwrap();
            tx.execute(
                "INSERT INTO publication_intents VALUES (?1, ?2, ?3)",
                ("one", "stage-one", 1),
            )
            .unwrap();
            // Simulated caller failure: dropping the transaction must roll back.
        }
        let count: i64 = db
            .connection
            .query_row("SELECT count(*) FROM publication_intents", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        {
            let tx = db.connection.transaction().unwrap();
            tx.execute(
                "INSERT INTO publication_intents VALUES (?1, ?2, ?3)",
                ("two", "stage-two", 2),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        drop(db);
        let db = MetadataDb::open(root.path()).unwrap();
        let name: String = db
            .connection
            .query_row(
                "SELECT stage_name FROM publication_intents WHERE object_id = ?1",
                ["two"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "stage-two");
    }
    #[test]
    fn failed_migration_rolls_back_schema_and_version() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE publication_intents (object_id TEXT PRIMARY KEY NOT NULL, stage_name TEXT NOT NULL, created_at INTEGER NOT NULL); PRAGMA user_version = 1;").unwrap();
        assert!(migrate_to_v2(&mut db, true).is_err());
        let version: i64 = db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'verified_archives'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(count, 0);
        migrate_to_v2(&mut db, false).unwrap();
        let version: i64 = db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }
}
