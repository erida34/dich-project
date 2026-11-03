use dich_apt::{
    FreshnessPolicy, SnapshotJournal, parse_control_stanzas, validate_release,
    verify_configured_inrelease,
};
use dich_store::{GcMode, MetadataDb};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

fn test_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn generate_synthetic_packages(count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count * 200);
    for i in 0..count {
        writeln!(out, "Package: pkg-{i:05}").unwrap();
        writeln!(out, "Version: 1.0.0-{i}").unwrap();
        writeln!(out, "Architecture: amd64").unwrap();
        writeln!(out, "Maintainer: Test <test@example.org>").unwrap();
        writeln!(out, "Installed-Size: 1024").unwrap();
        if i > 0 {
            writeln!(out, "Depends: pkg-{:05} (>= 1.0.0)", i - 1).unwrap();
        }
        writeln!(
            out,
            "Filename: pool/main/p/pkg-{i:05}/pkg-{i:05}_1.0.0-{i}_amd64.deb"
        )
        .unwrap();
        writeln!(out, "Size: 42000").unwrap();
        writeln!(
            out,
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        .unwrap();
        writeln!(out, "Description: Synthetic benchmark package {i}").unwrap();
        writeln!(out).unwrap();
    }
    out
}

fn bench_cold_metadata_parsing() {
    println!("\n--- Benchmark 1: Cold Metadata Parsing (5,000 package stanzas) ---");
    let count = 5_000;
    let packages_data = generate_synthetic_packages(count);
    println!(
        "Generated synthetic Packages index: {:.2} MB",
        packages_data.len() as f64 / 1_048_576.0
    );

    // Warmup
    let _ = parse_control_stanzas(&packages_data).unwrap();

    let iterations = 5;
    let mut times = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let stanzas = parse_control_stanzas(&packages_data).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(stanzas.len(), count);
        times.push(elapsed);
    }

    let min = times.iter().min().unwrap();
    let max = times.iter().max().unwrap();
    let sum: Duration = times.iter().sum();
    let avg = sum / (times.len() as u32);
    let throughput = (count as f64) / avg.as_secs_f64();

    println!("Cold metadata parse: min: {min:?}, avg: {avg:?}, max: {max:?}");
    println!("Throughput: {throughput:.0} packages/sec");

    // Performance budget: <= 500 ms
    let budget = Duration::from_millis(500);
    assert!(
        avg <= budget,
        "Performance regression: cold metadata parsing avg {avg:?} exceeded budget {budget:?}"
    );
    println!("Budget (<= 500ms): PASSED");
}

fn bench_warm_metadata_revalidation() {
    println!("\n--- Benchmark 2: Warm Metadata Cache Revalidation ---");
    let temp = test_dir();
    let home = temp.path().join("gnupg");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();

    let gpg = |args: &[&str]| {
        Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(args)
            .output()
            .unwrap()
    };

    assert!(
        gpg(&[
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Bench <bench@example.invalid>",
            "ed25519",
            "sign",
            "0",
        ])
        .status
        .success()
    );

    let listing = gpg(&["--batch", "--with-colons", "--list-keys"]);
    let fingerprint = String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .unwrap()
        .split(':')
        .nth(9)
        .unwrap()
        .to_string();

    let keyring_path = temp.path().join("keyring.gpg");
    let exported = gpg(&["--export", &fingerprint]);
    fs::write(&keyring_path, &exported.stdout).unwrap();
    fs::set_permissions(&keyring_path, fs::Permissions::from_mode(0o600)).unwrap();

    let source_file = temp.path().join("bench.sources");
    fs::write(
        &source_file,
        format!(
            "Types: deb\nURIs: https://example.org/debian\nSuites: bench\nComponents: main\nSigned-By: {}\n",
            keyring_path.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&source_file, fs::Permissions::from_mode(0o600)).unwrap();

    let policy_path = temp.path().join("sources.toml");
    fs::write(
        &policy_path,
        format!(
            "[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bench\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"{}\"]\n",
            source_file.display(),
            keyring_path.display(),
            fingerprint
        ),
    )
    .unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();

    let sources = dich_apt::load_configured_sources(&policy_path).unwrap();
    let source = &sources[0];

    let release_text = "Origin: Debian\nSuite: bench\nCodename: bench\nDate: Tue, 03 Nov 2026 12:00:00 UTC\nValid-Until: Tue, 10 Nov 2026 12:00:00 UTC\nSHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n";
    let mut sign_child = Command::new("gpg")
        .env("GNUPGHOME", &home)
        .args(["--clear-sign", "--batch"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    sign_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(release_text.as_bytes())
        .unwrap();
    let inrelease_bytes = sign_child.wait_with_output().unwrap().stdout;

    let verified_rel = verify_configured_inrelease(source, &inrelease_bytes).unwrap();
    let freshness_policy = FreshnessPolicy::new(
        Duration::from_secs(86400 * 365),
        Duration::from_secs(3600),
        false,
    )
    .unwrap();
    let validated_rel = validate_release(
        &verified_rel,
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_710_800),
        freshness_policy,
    )
    .unwrap();

    let cache_dir = temp.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = SnapshotJournal::open(&cache_dir).unwrap();
    journal.store_release(&validated_rel).unwrap();

    let iterations = 10;
    let mut times = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let loaded_rel = journal.load_release(source, freshness_policy).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(loaded_rel.source().uri(), source.uri());
        times.push(elapsed);
    }

    let min = times.iter().min().unwrap();
    let max = times.iter().max().unwrap();
    let sum: Duration = times.iter().sum();
    let avg = sum / (times.len() as u32);

    println!("Warm cache revalidation: min: {min:?}, avg: {avg:?}, max: {max:?}");
    let budget = if cfg!(debug_assertions) {
        Duration::from_millis(100)
    } else {
        Duration::from_millis(40)
    };
    assert!(
        avg <= budget,
        "Performance regression: warm metadata revalidation avg {avg:?} exceeded budget {budget:?}"
    );
    println!("Budget (<= {budget:?}): PASSED");
}

fn bench_package_deduplication() {
    println!("\n--- Benchmark 3: Package Deduplication Lookup & Reuse ---");
    let temp = test_dir();
    let store_dir = temp.path().join("store");
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let db = MetadataDb::open(&store_dir).unwrap();
    drop(db);

    // Populate store database with an initial object
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

    let iterations = 1_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let exists: bool = stmt.query_row([fake_id], |row| row.get(0)).unwrap();
        assert!(exists);
    }
    let total = start.elapsed();
    let per_lookup = total / (iterations as u32);

    println!("1,000 dedup lookups in {total:?} (avg {per_lookup:?} per lookup)");
    let throughput = (iterations as f64) / total.as_secs_f64();
    println!("Dedup query throughput: {throughput:.0} lookups/sec");

    let budget = Duration::from_millis(5);
    assert!(
        per_lookup <= budget,
        "Performance regression: dedup lookup {per_lookup:?} exceeded budget {budget:?}"
    );
    println!("Budget (<= 5ms per lookup): PASSED");
}

fn bench_garbage_collection() {
    println!("\n--- Benchmark 4: Garbage Collection (1,000 objects graph traversal & sweep) ---");
    let temp = test_dir();
    let store_dir = temp.path().join("store");
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let db = MetadataDb::open(&store_dir).unwrap();
    drop(db);

    // Populate database with 1,000 objects in verified_trees
    let object_count = 1_000;
    let mut object_ids = Vec::with_capacity(object_count);
    let db_path = store_dir.join("metadata.sqlite3");
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        let tx = conn.transaction().unwrap();
        for i in 0..object_count {
            let id = format!("{i:064x}");
            tx.execute(
                "INSERT INTO verified_trees (object_id, manifest, tree_manifest, total_size) VALUES (?1, ?2, ?3, 1024)",
                rusqlite::params![id, b"manifest", b"tree_manifest"],
            )
            .unwrap();
            object_ids.push(id);
        }
        tx.commit().unwrap();
    }

    let mut db = MetadataDb::open(&store_dir).unwrap();

    // Warmup
    let _ = db.collect_garbage(GcMode::DryRun).unwrap();

    let iterations = 5;
    let mut times = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let report = db.collect_garbage(GcMode::DryRun).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(report.unreachable_trees.len(), object_count);
        times.push(elapsed);
    }

    let min = times.iter().min().unwrap();
    let max = times.iter().max().unwrap();
    let sum: Duration = times.iter().sum();
    let avg = sum / (times.len() as u32);

    println!("GC dry-run (1,000 objects): min: {min:?}, avg: {avg:?}, max: {max:?}");
    let budget = Duration::from_millis(50);
    assert!(
        avg <= budget,
        "Performance regression: GC dry-run avg {avg:?} exceeded budget {budget:?}"
    );
    println!("Budget (<= 50ms): PASSED");
}

fn main() {
    println!("============================================================");
    println!(" DICH PERFORMANCE BENCHMARKS & BUDGET VERIFICATION");
    println!("============================================================");

    bench_cold_metadata_parsing();
    bench_warm_metadata_revalidation();
    bench_package_deduplication();
    bench_garbage_collection();

    println!("\n============================================================");
    println!(" ALL BENCHMARKS COMPLETED WITHIN PERFORMANCE BUDGETS");
    println!("============================================================");
}
