#![cfg(target_os = "linux")]
use dich_apt::{
    FreshnessPolicy, IndexLimits, SnapshotJournal, authorize_artifact, choose_index_format,
    load_configured_sources, select_indexed_artifact,
};
use dich_deb::{Limits, stage_cached};
use std::{
    path::Path,
    time::{Duration, SystemTime},
};

#[test]
#[ignore = "requires configured Ubuntu noble source, network and temporary cache"]
fn stages_verified_ubuntu_artifact_without_running_scripts() {
    let config = std::env::var("DICH_TEST_CONFIG").unwrap();
    let cache = std::env::var("DICH_TEST_CACHE").unwrap();
    let source = load_configured_sources(Path::new(&config))
        .unwrap()
        .remove(0);
    let journal = SnapshotJournal::open(Path::new(&cache)).unwrap();
    let freshness = FreshnessPolicy::new(
        Duration::from_secs(3 * 366 * 86400),
        Duration::from_secs(300),
        false,
    )
    .unwrap();
    let release = journal.load_release(&source, freshness).unwrap();
    let format = choose_index_format(&release, "main").unwrap();
    let (release, index) = journal
        .load_index(&source, freshness, "main", format, IndexLimits::default())
        .unwrap();
    let metadata = select_indexed_artifact(&index, "alsa-topology-conf", "1.2.5.1-2").unwrap();
    let authorized = authorize_artifact(&release, &metadata, SystemTime::now()).unwrap();
    let verified = journal.fetch_artifact(&authorized, 1_000_000).unwrap();
    journal.store_artifact(&authorized, verified).unwrap();
    let stage = stage_cached(&journal, &authorized, Limits::default()).unwrap();
    assert!(stage.is_bound_to(&authorized));
    let file = stage
        .open_file("lib/firmware/skl_hda_dsp_generic-tplg.bin")
        .unwrap();
    assert!(file.metadata().unwrap().is_file());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
}
