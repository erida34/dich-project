#![cfg(target_os = "linux")]
use dich_apt::{AuthenticatedUniverse, FreshnessPolicy, SnapshotJournal, load_configured_sources};
use dich_core::{ArchitecturePolicy, Distribution};
use std::{path::Path, time::Duration};

#[test]
#[ignore = "requires explicitly configured local Ubuntu noble authenticated cache"]
fn loads_real_ubuntu_noble_cache_under_explicit_policy() {
    let config = std::env::var("DICH_TEST_CONFIG").unwrap();
    let cache = std::env::var("DICH_TEST_CACHE").unwrap();
    let sources = load_configured_sources(Path::new(&config)).unwrap();
    assert_eq!(sources.len(), 1);
    let journal = SnapshotJournal::open(Path::new(&cache)).unwrap();
    let freshness = FreshnessPolicy::new(
        Duration::from_secs(3 * 366 * 86400),
        Duration::from_secs(300),
        false,
    )
    .unwrap();
    let policy = ArchitecturePolicy::new(Distribution::Ubuntu, "noble", "amd64").unwrap();
    let universe = AuthenticatedUniverse::load(&sources[0], &journal, freshness, &policy).unwrap();
    assert!(universe.package_count() > 1000);
}
