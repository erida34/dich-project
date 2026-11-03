#![cfg(target_os = "linux")]
use dich_apt::parse_control_stanzas;
use dich_store::{GcMode, MetadataDb};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn test_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn cold_metadata_parsing_performance_budget() {
    let count = 5_000;
    let mut out = Vec::with_capacity(count * 200);
    for i in 0..count {
        writeln!(out, "Package: test-pkg-{i:05}").unwrap();
        writeln!(out, "Version: 1.0.0-{i}").unwrap();
        writeln!(out, "Architecture: amd64").unwrap();
        writeln!(out, "Filename: pool/main/t/test/test-pkg-{i:05}.deb").unwrap();
        writeln!(out, "Size: 12345").unwrap();
        writeln!(
            out,
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        .unwrap();
        writeln!(out, "Description: Package {i}").unwrap();
        writeln!(out).unwrap();
    }

    let start = Instant::now();
    let stanzas = parse_control_stanzas(&out).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(stanzas.len(), count);
    let budget = Duration::from_millis(500);
    assert!(
        elapsed <= budget,
        "Cold metadata parse took {elapsed:?}, exceeding budget {budget:?}"
    );
}

#[test]
fn package_deduplication_lookup_performance_budget() {
    let temp = test_dir();
    let store_dir = temp.path().join("store");
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let db = MetadataDb::open(&store_dir).unwrap();
    drop(db);

    let fake_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let db_path = store_dir.join("metadata.sqlite3");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO verified_trees (object_id, manifest, tree_manifest, total_size) VALUES (?1, ?2, ?3, 1024)",
            rusqlite::params![fake_id, b"manifest", b"tree_manifest"],
        )
        .unwrap();
    }

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT EXISTS(SELECT 1 FROM verified_trees WHERE object_id = ?1)")
        .unwrap();

    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        let exists: bool = stmt.query_row([fake_id], |row| row.get(0)).unwrap();
        assert!(exists);
    }
    let elapsed = start.elapsed();
    let per_lookup = elapsed / iterations;

    let budget = Duration::from_millis(5);
    assert!(
        per_lookup <= budget,
        "Dedup lookup took {per_lookup:?}, exceeding budget {budget:?}"
    );
}

#[test]
fn garbage_collection_sweep_performance_budget() {
    let temp = test_dir();
    let store_dir = temp.path().join("store");
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let db = MetadataDb::open(&store_dir).unwrap();
    drop(db);

    // Populate database with 500 store objects in verified_trees
    let db_path = store_dir.join("metadata.sqlite3");
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        let tx = conn.transaction().unwrap();
        for i in 0..500 {
            let id = format!("{i:064x}");
            tx.execute(
                "INSERT INTO verified_trees (object_id, manifest, tree_manifest, total_size) VALUES (?1, ?2, ?3, 1024)",
                rusqlite::params![id, b"manifest", b"tree_manifest"],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    let mut db = MetadataDb::open(&store_dir).unwrap();
    let start = Instant::now();
    let report = db.collect_garbage(GcMode::DryRun).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(report.roots.active_profiles.len(), 0);
    assert_eq!(report.unreachable_trees.len(), 500);

    let budget = Duration::from_millis(50);
    assert!(
        elapsed <= budget,
        "GC dry run took {elapsed:?}, exceeding budget {budget:?}"
    );
}
