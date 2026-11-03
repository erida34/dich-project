#![cfg(target_os = "linux")]
use std::{fs, process::Command};

#[test]
fn signed_cached_archive_can_publish_a_tree_without_running_scripts() {
    use dich_apt::{
        FreshnessPolicy, IndexFormat, IndexLimits, SnapshotJournal, load_configured_sources,
        validate_release, verify_configured_inrelease,
    };
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt,
        process::Stdio,
        time::{Duration, SystemTime},
    };
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let home = dir.path().join("gnupg");
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
            "Dich publish fixture <test@example.invalid>",
            "ed25519",
            "sign",
            "0"
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
        .to_owned();
    let keyring = dir.path().join("keyring.gpg");
    let exported = gpg(&["--batch", "--export", &fingerprint]);
    assert!(exported.status.success());
    fs::write(&keyring, exported.stdout).unwrap();
    let source_file = dir.path().join("fixture.sources");
    let config = dir.path().join("sources.toml");
    let cache_dir = dir.path().join("cache");
    let store_dir = dir.path().join("store");
    fs::create_dir(&cache_dir).unwrap();
    fs::create_dir(&store_dir).unwrap();
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&source_file, format!("Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {}\n", keyring.display())).unwrap();
    fs::write(&config, format!("[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"{}\"]\n", source_file.display(), keyring.display(), fingerprint)).unwrap();
    let marker = dir.path().join("script-executed");
    let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
    let make_tar = |entries: &[(&str, &[u8])]| {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            for &(path, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, content).unwrap();
            }
            builder.finish().unwrap();
        }
        bytes
    };
    let control = make_tar(&[
        (
            "control",
            b"Package: fixturetree\nVersion: 1.0-1\nArchitecture: amd64\n",
        ),
        ("postinst", script.as_bytes()),
    ]);
    let data = make_tar(&[("usr/share/fixturetree/data", b"fixture content")]);
    let make_deb = |control: Vec<u8>, data: Vec<u8>| {
        let mut archive = Vec::new();
        let mut builder = ar::Builder::new(&mut archive);
        for (name, body) in [
            ("debian-binary", b"2.0\n".to_vec()),
            ("control.tar", control),
            ("data.tar", data),
        ] {
            let header = ar::Header::new(name.as_bytes().to_vec(), body.len() as u64);
            builder.append(&header, body.as_slice()).unwrap();
        }
        archive
    };
    let archive = make_deb(control, data);
    let source = dir.path().join("fixture.c");
    let library_path = dir.path().join("libfixture.so");
    fs::write(&source, b"int fixture_value(void) { return 7; }\n").unwrap();
    let compiled = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-Wl,-soname,libfixture.so",
            "-o",
        ])
        .arg(&library_path)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let library = fs::read(&library_path).unwrap();
    let library_control = make_tar(&[(
        "control",
        b"Package: fixturelib\nVersion: 1.0-1\nArchitecture: amd64\n",
    )]);
    let library_data = make_tar(&[("usr/lib/x86_64-linux-gnu/libfixture.so", &library)]);
    let library_archive = make_deb(library_control, library_data);
    let library_v2_path = dir.path().join("libfixture-v2.so");
    fs::write(&source, b"int fixture_value(void) { return 8; }\n").unwrap();
    let compiled = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-Wl,-soname,libfixture.so",
            "-o",
        ])
        .arg(&library_v2_path)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let library_v2 = fs::read(&library_v2_path).unwrap();
    let library_v2_control = make_tar(&[(
        "control",
        b"Package: fixturelib\nVersion: 2.0-1\nArchitecture: amd64\n",
    )]);
    let library_v2_data = make_tar(&[("usr/lib/x86_64-linux-gnu/libfixture.so", &library_v2)]);
    let library_v2_archive = make_deb(library_v2_control, library_v2_data);

    let common_so = include_bytes!("../../dich-elf/tests/fixtures/shared-libcommon.so");
    let plugin_v1_so = include_bytes!("../../dich-elf/tests/fixtures/shared-libplugin-v1.so");
    let plugin_v2_so = include_bytes!("../../dich-elf/tests/fixtures/shared-libplugin-v2.so");
    let common_control = make_tar(&[(
        "control",
        b"Package: libdich-common\nVersion: 1.0-1\nArchitecture: amd64\n",
    )]);
    let common_data = make_tar(&[("usr/lib/x86_64-linux-gnu/libcommon.so", common_so)]);
    let common_archive = make_deb(common_control, common_data);

    let plugin_v1_control = make_tar(&[(
        "control",
        b"Package: dich-plugin\nVersion: 1.0-1\nArchitecture: amd64\nDepends: libdich-common (= 1.0-1)\n",
    )]);
    let plugin_v1_data = make_tar(&[("usr/lib/x86_64-linux-gnu/libplugin.so", plugin_v1_so)]);
    let plugin_v1_archive = make_deb(plugin_v1_control, plugin_v1_data);

    let plugin_v2_control = make_tar(&[(
        "control",
        b"Package: dich-plugin\nVersion: 2.0-1\nArchitecture: amd64\nDepends: libdich-common (= 1.0-1)\n",
    )]);
    let plugin_v2_data = make_tar(&[("usr/lib/x86_64-linux-gnu/libplugin.so", plugin_v2_so)]);
    let plugin_v2_archive = make_deb(plugin_v2_control, plugin_v2_data);
    let hex = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let artifact_hash = hex(&archive);
    let package_index = format!(
        "Package: fixturetree\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/f/fixturetree/fixturetree_1.0-1_amd64.deb\nSize: {}\nSHA256: {}\n\n",
        archive.len(),
        artifact_hash
    ) + &format!(
        "Package: fixturelib\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/f/fixturelib/fixturelib_1.0-1_amd64.deb\nSize: {}\nSHA256: {}\n\n",
        library_archive.len(),
        hex(&library_archive)
    ) + &format!(
        "Package: fixturelib\nVersion: 2.0-1\nArchitecture: amd64\nFilename: pool/main/f/fixturelib/fixturelib_2.0-1_amd64.deb\nSize: {}\nSHA256: {}\n\n",
        library_v2_archive.len(),
        hex(&library_v2_archive)
    ) + &format!(
        "Package: libdich-common\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/libd/libdich-common/libdich-common_1.0-1_amd64.deb\nSize: {}\nSHA256: {}\n\n",
        common_archive.len(),
        hex(&common_archive)
    ) + &format!(
        "Package: dich-plugin\nVersion: 1.0-1\nArchitecture: amd64\nDepends: libdich-common (= 1.0-1)\nFilename: pool/main/d/dich-plugin/dich-plugin_1.0-1_amd64.deb\nSize: {}\nSHA256: {}\n\n",
        plugin_v1_archive.len(),
        hex(&plugin_v1_archive)
    ) + &format!(
        "Package: dich-plugin\nVersion: 2.0-1\nArchitecture: amd64\nDepends: libdich-common (= 1.0-1)\nFilename: pool/main/d/dich-plugin/dich-plugin_2.0-1_amd64.deb\nSize: {}\nSHA256: {}\n\n",
        plugin_v2_archive.len(),
        hex(&plugin_v2_archive)
    );
    let mut gzip = Command::new("gzip")
        .args(["-n", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    gzip.stdin
        .take()
        .unwrap()
        .write_all(package_index.as_bytes())
        .unwrap();
    let compressed = gzip.wait_with_output().unwrap();
    assert!(compressed.status.success());
    let date = Command::new("date")
        .args(["-u", "+%a, %d %b %Y %H:%M:%S UTC"])
        .output()
        .unwrap();
    let release = format!(
        "Origin: Debian\nSuite: bookworm\nDate: {}SHA256:\n {} {} main/binary-amd64/Packages.gz\n",
        String::from_utf8(date.stdout).unwrap(),
        hex(&compressed.stdout),
        compressed.stdout.len()
    );
    let release_path = dir.path().join("Release-publish");
    let signed_path = dir.path().join("InRelease-publish");
    fs::write(&release_path, release).unwrap();
    let signed = gpg(&[
        "--batch",
        "--yes",
        "--clearsign",
        "--output",
        signed_path.to_str().unwrap(),
        release_path.to_str().unwrap(),
    ]);
    assert!(signed.status.success());
    let source = load_configured_sources(&config).unwrap().remove(0);
    let verified = verify_configured_inrelease(&source, &fs::read(&signed_path).unwrap()).unwrap();
    let freshness =
        FreshnessPolicy::new(Duration::from_secs(86400), Duration::from_secs(300), false).unwrap();
    let release = validate_release(&verified, SystemTime::now(), freshness).unwrap();
    let journal = SnapshotJournal::open(&cache_dir).unwrap();
    journal.store_release(&release).unwrap();
    journal
        .store_index(
            &release,
            "main",
            IndexFormat::Gzip,
            &compressed.stdout,
            IndexLimits::default(),
        )
        .unwrap();
    let blob = cache_dir.join(format!("blob-{artifact_hash}"));
    fs::write(&blob, archive).unwrap();
    fs::set_permissions(blob, fs::Permissions::from_mode(0o600)).unwrap();
    let library_hash = hex(&library_archive);
    let library_blob = cache_dir.join(format!("blob-{library_hash}"));
    fs::write(&library_blob, library_archive).unwrap();
    fs::set_permissions(library_blob, fs::Permissions::from_mode(0o600)).unwrap();
    let library_v2_hash = hex(&library_v2_archive);
    let library_v2_blob = cache_dir.join(format!("blob-{library_v2_hash}"));
    fs::write(&library_v2_blob, library_v2_archive).unwrap();
    fs::set_permissions(library_v2_blob, fs::Permissions::from_mode(0o600)).unwrap();
    for archive_bytes in [&common_archive, &plugin_v1_archive, &plugin_v2_archive] {
        let hash = hex(archive_bytes);
        let blob = cache_dir.join(format!("blob-{hash}"));
        fs::write(&blob, archive_bytes).unwrap();
        fs::set_permissions(blob, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let fetch = || {
        Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--store-dir",
                store_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "fetch",
                "fixturetree",
                "--exact-version",
                "1.0-1",
                "--component",
                "main",
                "--publish-tree",
            ])
            .output()
            .unwrap()
    };
    let result = fetch();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["state"], "cached");
    assert_eq!(body["tree"]["publication"], "published");
    assert_eq!(body["tree"]["lifecycle"], "extracted");
    assert_eq!(body["tree"]["compatibility"], "not_analyzed");
    assert_eq!(body["installable"], false);
    let id = body["tree"]["id"].as_str().unwrap();
    assert_eq!(
        fs::read(
            store_dir
                .join("objects")
                .join(format!("{id}.tree/usr/share/fixturetree/data"))
        )
        .unwrap(),
        b"fixture content"
    );
    assert!(!marker.exists());
    let verify = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "store",
            "verify",
            id,
            "--kind",
            "tree",
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verified: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verified["recorded_lifecycle"], "extracted");
    assert_eq!(verified["content_verified"], true);
    assert_eq!(verified["compatibility"], "not_analyzed");
    assert_eq!(verified["installable"], false);
    let reused = fetch();
    assert!(reused.status.success());
    let body: serde_json::Value = serde_json::from_slice(&reused.stdout).unwrap();
    assert_eq!(body["tree"]["publication"], "reused");
    assert!(!marker.exists());

    let install_args = [
        "--json",
        "--config",
        config.to_str().unwrap(),
        "--cache",
        cache_dir.to_str().unwrap(),
        "--store-dir",
        store_dir.to_str().unwrap(),
        "--max-age-seconds",
        "86400",
        "--allow-missing-valid-until",
        "install",
        "fixturelib",
        "--exact-version",
        "1.0-1",
    ];
    let planned = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(install_args)
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(plan["status"], "planned");
    assert_eq!(plan["exact_version"], "1.0-1");
    assert_eq!(plan["pins"][0]["version"], "1.0-1");
    assert_eq!(plan["requires_confirmation"], "--yes");
    let mut rejected_args = install_args.to_vec();
    let package_arg = rejected_args
        .iter()
        .position(|arg| *arg == "fixturelib")
        .unwrap();
    rejected_args[package_arg] = "fixturetree";
    let rejected = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(rejected_args)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let rejected: serde_json::Value = serde_json::from_slice(&rejected.stderr).unwrap();
    assert_eq!(rejected["error"]["code"], "compatibility_rejected");
    assert!(!marker.exists());
    let list = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "profile",
            "list",
        ])
        .output()
        .unwrap();
    assert!(list.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&list.stdout).unwrap()["profiles"],
        serde_json::json!([])
    );

    let installed = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(install_args)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let installed: serde_json::Value = serde_json::from_slice(&installed.stdout).unwrap();
    assert_eq!(installed["status"], "completed");
    assert_eq!(installed["requested_package"], "fixturelib");
    assert_eq!(installed["maintainer_scripts_executed"], false);
    let explicit_path = installed["objects"][0]["explicit_path"].as_str().unwrap();
    assert_eq!(fs::read(explicit_path).unwrap(), library);
    let first_generation = installed["generation_id"].as_str().unwrap().to_owned();

    let installed_v2 = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "install",
            "fixturelib",
            "--exact-version",
            "2.0-1",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(
        installed_v2.status.success(),
        "{}",
        String::from_utf8_lossy(&installed_v2.stderr)
    );
    let installed_v2: serde_json::Value = serde_json::from_slice(&installed_v2.stdout).unwrap();
    assert_eq!(installed_v2["objects"][0]["version"], "2.0-1");
    let second_generation = installed_v2["generation_id"].as_str().unwrap();
    assert_ne!(first_generation, second_generation);
    let explicit_v2_path = installed_v2["objects"][0]["explicit_path"]
        .as_str()
        .unwrap();
    assert_eq!(fs::read(explicit_v2_path).unwrap(), library_v2);

    let rollback_args = [
        "--json",
        "--store-dir",
        store_dir.to_str().unwrap(),
        "rollback",
    ];
    let rollback_plan = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(rollback_args)
        .output()
        .unwrap();
    assert!(rollback_plan.status.success());
    let rollback_plan: serde_json::Value = serde_json::from_slice(&rollback_plan.stdout).unwrap();
    assert_eq!(rollback_plan["status"], "planned");
    assert_eq!(rollback_plan["target_generation"], first_generation);
    let rollback = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(rollback_args)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(
        rollback.status.success(),
        "{}",
        String::from_utf8_lossy(&rollback.stderr)
    );
    let rollback: serde_json::Value = serde_json::from_slice(&rollback.stdout).unwrap();
    assert_eq!(rollback["generation_id"], first_generation);
    let active = dich_store::MetadataDb::open_existing(&store_dir).unwrap();
    assert_eq!(
        active
            .read_profile_generation("default")
            .unwrap()
            .unwrap()
            .generation_id,
        first_generation
    );
    drop(active);

    let list = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "profile",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let profiles: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(profiles["profiles"][0]["requested_package"], "fixturelib");

    let remove_args = [
        "--json",
        "--store-dir",
        store_dir.to_str().unwrap(),
        "remove",
        "fixturelib",
    ];
    let remove_plan = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(remove_args)
        .output()
        .unwrap();
    assert!(remove_plan.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&remove_plan.stdout).unwrap()["status"],
        "planned"
    );
    let removed = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(remove_args)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&removed.stdout).unwrap()["objects_retained"],
        true
    );
    let list = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "profile",
            "list",
        ])
        .output()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&list.stdout).unwrap()["profiles"],
        serde_json::json!([])
    );
    assert!(!marker.exists());

    let plugin_args = [
        "--json",
        "--config",
        config.to_str().unwrap(),
        "--cache",
        cache_dir.to_str().unwrap(),
        "--store-dir",
        store_dir.to_str().unwrap(),
        "--max-age-seconds",
        "86400",
        "--allow-missing-valid-until",
        "install",
        "dich-plugin",
        "--profile",
        "plugins",
        "--exact-version",
        "1.0-1",
    ];
    let plugin_plan = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(plugin_args)
        .output()
        .unwrap();
    assert!(
        plugin_plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plugin_plan.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&plugin_plan.stdout).unwrap();
    assert_eq!(plan["status"], "planned");
    assert_eq!(plan["root_package"], "dich-plugin=1.0-1");
    assert_eq!(
        plan["dependency_edges"],
        serde_json::json!([["dich-plugin=1.0-1", "libdich-common=1.0-1"]])
    );

    let plugin_install = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(plugin_args)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(
        plugin_install.status.success(),
        "{}",
        String::from_utf8_lossy(&plugin_install.stderr)
    );
    let installed: serde_json::Value = serde_json::from_slice(&plugin_install.stdout).unwrap();
    assert_eq!(installed["status"], "completed");
    assert_eq!(installed["requested_package"], "dich-plugin");
    assert_eq!(installed["maintainer_scripts_executed"], false);
    let objects = installed["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 2);
    let common_obj = objects
        .iter()
        .find(|o| o["package"] == "libdich-common")
        .unwrap();
    let plugin_obj = objects
        .iter()
        .find(|o| o["package"] == "dich-plugin")
        .unwrap();
    assert_eq!(common_obj["publication"], "published");
    assert_eq!(plugin_obj["publication"], "published");

    let common_path = common_obj["explicit_path"].as_str().unwrap();
    let plugin_path = plugin_obj["explicit_path"].as_str().unwrap();
    assert!(fs::metadata(common_path).unwrap().is_file());
    assert!(fs::metadata(plugin_path).unwrap().is_file());

    let checker = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dich-elf/tests/fixtures/dlmopen-checker"
    );
    let runtime_check = Command::new(checker)
        .arg(common_path)
        .arg(plugin_path)
        .arg("43")
        .status()
        .unwrap();
    assert!(
        runtime_check.success(),
        "runtime loading installed signed DSO closure failed"
    );

    let first_plugin_generation = installed["generation_id"].as_str().unwrap().to_owned();

    let db = dich_store::MetadataDb::open_existing(&store_dir).unwrap();
    let profile_gen = db.read_profile_generation("plugins").unwrap().unwrap();
    assert_eq!(
        profile_gen.requested_package.as_deref(),
        Some("dich-plugin")
    );
    let graph = db.read_reference_graph(&profile_gen.graph_id).unwrap();
    assert_eq!(graph.roots(), &[plugin_obj["object_id"].as_str().unwrap()]);
    assert_eq!(
        graph.edges(),
        &[(
            plugin_obj["object_id"].as_str().unwrap().to_owned(),
            common_obj["object_id"].as_str().unwrap().to_owned()
        )]
    );
    drop(db);

    let plugin_v2_args = [
        "--json",
        "--config",
        config.to_str().unwrap(),
        "--cache",
        cache_dir.to_str().unwrap(),
        "--store-dir",
        store_dir.to_str().unwrap(),
        "--max-age-seconds",
        "86400",
        "--allow-missing-valid-until",
        "install",
        "dich-plugin",
        "--profile",
        "plugins",
        "--exact-version",
        "2.0-1",
        "--yes",
    ];
    let plugin_v2_install = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(plugin_v2_args)
        .output()
        .unwrap();
    assert!(
        plugin_v2_install.status.success(),
        "{}",
        String::from_utf8_lossy(&plugin_v2_install.stderr)
    );
    let installed_v2: serde_json::Value =
        serde_json::from_slice(&plugin_v2_install.stdout).unwrap();
    let objects_v2 = installed_v2["objects"].as_array().unwrap();
    let common_obj_v2 = objects_v2
        .iter()
        .find(|o| o["package"] == "libdich-common")
        .unwrap();
    let plugin_obj_v2 = objects_v2
        .iter()
        .find(|o| o["package"] == "dich-plugin")
        .unwrap();
    assert_eq!(common_obj_v2["publication"], "reused");
    assert_eq!(common_obj_v2["object_id"], common_obj["object_id"]);
    assert_eq!(plugin_obj_v2["publication"], "published");

    let plugin_v2_path = plugin_obj_v2["explicit_path"].as_str().unwrap();
    let runtime_check_v2 = Command::new(checker)
        .arg(common_path)
        .arg(plugin_v2_path)
        .arg("44")
        .status()
        .unwrap();
    assert!(
        runtime_check_v2.success(),
        "runtime loading v2 installed signed DSO closure failed"
    );

    let rollback_args = [
        "--json",
        "--store-dir",
        store_dir.to_str().unwrap(),
        "rollback",
        "--profile",
        "plugins",
    ];
    let rollback = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(rollback_args)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(rollback.status.success());
    let rollback_res: serde_json::Value = serde_json::from_slice(&rollback.stdout).unwrap();
    assert_eq!(rollback_res["generation_id"], first_plugin_generation);

    let runtime_check_rb = Command::new(checker)
        .arg(common_path)
        .arg(plugin_path)
        .arg("43")
        .status()
        .unwrap();
    assert!(
        runtime_check_rb.success(),
        "runtime loading after rollback failed"
    );

    let remove_plugin = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "remove",
            "dich-plugin",
            "--profile",
            "plugins",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(remove_plugin.status.success());
    assert!(!marker.exists());

    // --- Phase 5 GC Smoke Test: A/B variants, dependency dedup, remove one, GC preserves shared library, rollback ---

    // 1. Install Variant A (dich-plugin 1.0) into profile-a
    let install_a = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "install",
            "dich-plugin",
            "--profile",
            "profile-a",
            "--exact-version",
            "1.0-1",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(
        install_a.status.success(),
        "{}",
        String::from_utf8_lossy(&install_a.stderr)
    );
    let installed_a: serde_json::Value = serde_json::from_slice(&install_a.stdout).unwrap();
    let obj_a = installed_a["objects"].as_array().unwrap();
    let common_in_a = obj_a
        .iter()
        .find(|o| o["package"] == "libdich-common")
        .unwrap();
    let plugin_in_a = obj_a
        .iter()
        .find(|o| o["package"] == "dich-plugin")
        .unwrap();
    assert_eq!(common_in_a["publication"], "reused");
    assert_eq!(common_in_a["object_id"], common_obj["object_id"]);

    // 2. Install Variant B (dich-plugin 2.0) into profile-b
    let install_b = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "install",
            "dich-plugin",
            "--profile",
            "profile-b",
            "--exact-version",
            "2.0-1",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(
        install_b.status.success(),
        "{}",
        String::from_utf8_lossy(&install_b.stderr)
    );
    let installed_b: serde_json::Value = serde_json::from_slice(&install_b.stdout).unwrap();
    let obj_b = installed_b["objects"].as_array().unwrap();
    let common_in_b = obj_b
        .iter()
        .find(|o| o["package"] == "libdich-common")
        .unwrap();
    let plugin_in_b = obj_b
        .iter()
        .find(|o| o["package"] == "dich-plugin")
        .unwrap();
    assert_eq!(common_in_b["publication"], "reused");
    assert_eq!(common_in_b["object_id"], common_obj["object_id"]);

    // Verify both variants execute cleanly via dlmopen
    let check_a = Command::new(checker)
        .arg(common_in_a["explicit_path"].as_str().unwrap())
        .arg(plugin_in_a["explicit_path"].as_str().unwrap())
        .arg("43")
        .status()
        .unwrap();
    assert!(check_a.success(), "profile-a runtime failed");

    let check_b = Command::new(checker)
        .arg(common_in_b["explicit_path"].as_str().unwrap())
        .arg(plugin_in_b["explicit_path"].as_str().unwrap())
        .arg("44")
        .status()
        .unwrap();
    assert!(check_b.success(), "profile-b runtime failed");

    // 3. Remove Variant B (profile-b)
    let remove_b = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "remove",
            "dich-plugin",
            "--profile",
            "profile-b",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(remove_b.status.success());

    // 4. Test GC dry-run
    let gc_dry = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "gc",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(gc_dry.status.success());
    let dry_json: serde_json::Value = serde_json::from_slice(&gc_dry.stdout).unwrap();
    assert_eq!(dry_json["status"], "planned");
    assert_eq!(dry_json["mode"], "dry-run");
    let unreach_trees = dry_json["unreachable"]["trees"].as_array().unwrap();
    assert!(
        unreach_trees
            .iter()
            .any(|t| t["object_id"] == plugin_in_b["object_id"].as_str().unwrap()),
        "unreachable plugin-b must be detected"
    );
    assert!(
        !unreach_trees
            .iter()
            .any(|t| t["object_id"] == plugin_in_a["object_id"].as_str().unwrap()),
        "active plugin-a must NOT be unreachable"
    );
    assert!(
        !unreach_trees
            .iter()
            .any(|t| t["object_id"] == common_in_a["object_id"].as_str().unwrap()),
        "shared common library must NOT be unreachable"
    );
    assert!(dry_json["summary"]["reclaimable_bytes"].as_u64().unwrap() > 0);
    assert_eq!(dry_json["summary"]["reclaimed_bytes"].as_u64().unwrap(), 0);

    // Human-readable dry-run output diagnostics
    let gc_human = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--store-dir", store_dir.to_str().unwrap(), "gc"])
        .output()
        .unwrap();
    assert!(gc_human.status.success());
    let human_out = String::from_utf8_lossy(&gc_human.stdout);
    assert!(human_out.contains("Garbage collection (dry-run):"));
    assert!(human_out.contains("Active profiles: profile-a"));
    assert!(human_out.contains("Reclaimable space:"));

    // Verify plugin-b tree still exists on disk before execute
    let plugin_b_tree = store_dir.join(format!(
        "objects/{}.tree",
        plugin_in_b["object_id"].as_str().unwrap()
    ));
    assert!(plugin_b_tree.exists());

    // 5. Test GC execute
    let gc_exec = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "gc",
            "--execute",
        ])
        .output()
        .unwrap();
    assert!(gc_exec.status.success());
    let exec_json: serde_json::Value = serde_json::from_slice(&gc_exec.stdout).unwrap();
    assert_eq!(exec_json["status"], "completed");
    assert_eq!(exec_json["mode"], "execute");
    assert_eq!(
        exec_json["summary"]["reclaimed_bytes"],
        dry_json["summary"]["reclaimable_bytes"]
    );

    // Verify plugin-b tree is deleted from disk, but shared libdich-common and profile-a's plugin are preserved!
    assert!(
        !plugin_b_tree.exists(),
        "unreachable plugin-b tree should be deleted"
    );
    let common_tree = store_dir.join(format!(
        "objects/{}.tree",
        common_in_a["object_id"].as_str().unwrap()
    ));
    let plugin_a_tree = store_dir.join(format!(
        "objects/{}.tree",
        plugin_in_a["object_id"].as_str().unwrap()
    ));
    assert!(
        common_tree.exists(),
        "shared libdich-common tree must be preserved"
    );
    assert!(
        plugin_a_tree.exists(),
        "active profile-a plugin tree must be preserved"
    );

    // 6. Verify profile-a runtime check still succeeds (preserves shared library!)
    let check_a_after_gc = Command::new(checker)
        .arg(common_in_a["explicit_path"].as_str().unwrap())
        .arg(plugin_in_a["explicit_path"].as_str().unwrap())
        .arg("43")
        .status()
        .unwrap();
    assert!(
        check_a_after_gc.success(),
        "runtime check on profile-a failed after GC sweep"
    );

    // 7. Test rollback preservation with GC:
    // Upgrade profile-a to 2.0 (so profile-a current is 2.0, with 1.0 as previous_id rollback target)
    let upgrade_a = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--store-dir",
            store_dir.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "install",
            "dich-plugin",
            "--profile",
            "profile-a",
            "--exact-version",
            "2.0-1",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(upgrade_a.status.success());

    // Run GC while 2.0 is current: 1.0 must be preserved because it is in previous_id chain!
    let gc_while_upgraded = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "gc",
            "--execute",
        ])
        .output()
        .unwrap();
    assert!(gc_while_upgraded.status.success());
    let up_gc_json: serde_json::Value = serde_json::from_slice(&gc_while_upgraded.stdout).unwrap();
    assert_eq!(
        up_gc_json["unreachable"]["trees"].as_array().unwrap().len(),
        0,
        "both current 2.0 and rollback target 1.0 must be preserved"
    );

    // Rollback profile-a to 1.0 succeeds because GC preserved 1.0!
    let rollback_a = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "rollback",
            "--profile",
            "profile-a",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(rollback_a.status.success());

    // Now that profile-a rolled back to 1.0, 2.0 is an abandoned forward generation
    let gc_after_rollback = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--store-dir",
            store_dir.to_str().unwrap(),
            "gc",
            "--execute",
        ])
        .output()
        .unwrap();
    assert!(gc_after_rollback.status.success());
    let rb_gc_json: serde_json::Value = serde_json::from_slice(&gc_after_rollback.stdout).unwrap();
    assert_eq!(
        rb_gc_json["unreachable"]["trees"].as_array().unwrap().len(),
        1,
        "the rolled-back 2.0 package is now unreachable and swept"
    );

    // Verify profile-a (1.0) still runs cleanly with shared libdich-common
    let check_a_final = Command::new(checker)
        .arg(common_in_a["explicit_path"].as_str().unwrap())
        .arg(plugin_in_a["explicit_path"].as_str().unwrap())
        .arg("43")
        .status()
        .unwrap();
    assert!(
        check_a_final.success(),
        "profile-a must still execute successfully at v1"
    );
}

#[test]
fn lists_configured_sources_and_reports_json_errors() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let source = dir.path().join("example.sources");
    let config = dir.path().join("sources.toml");
    fs::write(&source, "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/example.gpg\n").unwrap();
    let policy = format!(
        "[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"/usr/share/keyrings/example.gpg\"\nfingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n",
        source.display()
    );
    fs::write(&config, policy).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "sources",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["sources"][0]["suite"], "bookworm");
    let missing = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "--config", "/no/such/config", "sources", "list"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let error: serde_json::Value = serde_json::from_slice(&missing.stderr).unwrap();
    assert_eq!(error["schema_version"], 1);
    assert_eq!(error["error"]["code"], "source_load_failed");
    let human = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--config", config.to_str().unwrap(), "sources", "list"])
        .output()
        .unwrap();
    assert!(human.status.success());
    assert!(
        String::from_utf8_lossy(&human.stdout)
            .contains("configured\thttps://example.org/debian\tbookworm\tamd64\tmain")
    );
    for args in [["--json", "install"], ["--json", "unknown"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["schema_version"], 1);
    }
    let update = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            dir.path().to_str().unwrap(),
            "update",
        ])
        .output()
        .unwrap();
    assert!(!update.status.success());
    let error: serde_json::Value = serde_json::from_slice(&update.stderr).unwrap();
    assert_eq!(error["error"]["code"], "freshness_policy_required");
    let query = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            dir.path().to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "search",
            "fixture",
        ])
        .output()
        .unwrap();
    assert!(!query.status.success());
    assert!(query.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&query.stderr).unwrap();
    assert_eq!(error["error"]["code"], "query_failed");
}

#[test]
fn cached_query_cli_outputs_authenticated_fixture_offline() {
    use dich_apt::{
        FreshnessPolicy, IndexFormat, IndexLimits, SnapshotJournal, load_configured_sources,
        validate_release, verify_configured_inrelease,
    };
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let home = dir.path().join("gnupg");
    fs::create_dir(&home).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let gpg = |args: &[&str]| {
        Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(args)
            .output()
            .unwrap()
    };
    let generated = gpg(&[
        "--batch",
        "--passphrase",
        "",
        "--quick-generate-key",
        "Dich test fixture <test@example.invalid>",
        "ed25519",
        "sign",
        "0",
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let listing = gpg(&["--batch", "--with-colons", "--list-keys"]);
    assert!(listing.status.success());
    let fingerprint = String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .unwrap()
        .split(':')
        .nth(9)
        .unwrap()
        .to_string();
    let keyring = dir.path().join("keyring.gpg");
    let exported = gpg(&["--batch", "--export", &fingerprint]);
    assert!(exported.status.success());
    fs::write(&keyring, exported.stdout).unwrap();
    let source_file = dir.path().join("fixture.sources");
    let config = dir.path().join("sources.toml");
    let cache_dir = dir.path().join("cache");
    fs::create_dir(&cache_dir).unwrap();
    fs::write(&source_file, format!("Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {}\n", keyring.display())).unwrap();
    fs::write(&config, format!("[[sources]]\ndistribution = \"debian\"\nsources_file = \"{}\"\nuri = \"https://example.org/debian\"\nsuite = \"bookworm\"\ncomponents = [\"main\"]\narchitecture = \"amd64\"\nkeyring = \"{}\"\nfingerprints = [\"{}\"]\n", source_file.display(), keyring.display(), fingerprint)).unwrap();
    let date = Command::new("date")
        .args(["-u", "+%a, %d %b %Y %H:%M:%S UTC"])
        .output()
        .unwrap();
    assert!(date.status.success());
    let date = String::from_utf8(date.stdout).unwrap();
    let release = format!(
        "Origin: Debian\nSuite: bookworm\nDate: {}SHA256:\n fa184974c07c71db02266b3a06849f8804e9e3930963a90102136ccabf99d0a5 224 main/binary-amd64/Packages.xz\n",
        date
    );
    let release_path = dir.path().join("Release");
    let signed_path = dir.path().join("InRelease");
    fs::write(&release_path, release).unwrap();
    let signed = gpg(&[
        "--batch",
        "--yes",
        "--clearsign",
        "--output",
        signed_path.to_str().unwrap(),
        release_path.to_str().unwrap(),
    ]);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let sources = load_configured_sources(&config).unwrap();
    let verified =
        verify_configured_inrelease(&sources[0], &fs::read(signed_path).unwrap()).unwrap();
    let policy =
        FreshnessPolicy::new(Duration::from_secs(86400), Duration::from_secs(300), false).unwrap();
    let release = validate_release(&verified, SystemTime::now(), policy).unwrap();
    let journal = SnapshotJournal::open(&cache_dir).unwrap();
    journal.store_release(&release).unwrap();
    journal
        .store_index(
            &release,
            "main",
            IndexFormat::Xz,
            include_bytes!("../../dich-apt/tests/fixtures/index/Packages.xz"),
            IndexLimits::default(),
        )
        .unwrap();
    let planned = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "plan",
            "fixture",
            "--distribution",
            "debian",
            "--suite",
            "bookworm",
            "--architecture",
            "amd64",
        ])
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(body["status"], "planned");
    assert_eq!(
        body["pins"][0]["artifact_sha256"],
        "0c190c47a57eaf9b339049983978ff0bec52a1d19576c679c40a366cba1d4bc6"
    );
    assert_eq!(body["pins"][0]["architecture"], "amd64");
    assert_eq!(body["pins"][0]["suite"], "bookworm");
    assert_eq!(
        body["pins"][0]["release_sha256"].as_str().unwrap().len(),
        64
    );
    assert_eq!(body["packages"], serde_json::json!(["fixture=1.0-1"]));
    assert!(
        body["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("fixture=1.0-1"))
    );
    for (name, distribution, expected) in [
        ("missing", "debian", "unsatisfiable"),
        ("fixture", "ubuntu", "plan_input_failed"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "plan",
                name,
                "--distribution",
                distribution,
                "--suite",
                "bookworm",
                "--architecture",
                "amd64",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], expected);
        if expected == "unsatisfiable" {
            assert!(!error["error"]["trace"].as_array().unwrap().is_empty());
        }
    }
    for command in ["search", "show", "versions"] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                command,
                "fixture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"schema_version":1,"status":"completed","records":[{"name":"fixture","version":"1.0-1","architecture":"amd64","source":"https://example.org/debian","suite":"bookworm"}]})
        );
    }
    for (name, version, max_bytes) in [("fixture", "1.0-1", "1"), ("fixture", "99", "1024")] {
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "fetch",
                name,
                "--exact-version",
                version,
                "--component",
                "main",
                "--max-bytes",
                max_bytes,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], "fetch_failed");
    }
    let blob =
        cache_dir.join("blob-0c190c47a57eaf9b339049983978ff0bec52a1d19576c679c40a366cba1d4bc6");
    let fixture = include_bytes!("../../dich-apt/tests/fixtures/index/fixture.deb");
    fs::write(&blob, fixture).unwrap();
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
    let cached_fetch = || {
        Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "fetch",
                "fixture",
                "--exact-version",
                "1.0-1",
                "--component",
                "main",
                "--max-bytes",
                "1024",
            ])
            .output()
            .unwrap()
    };
    let cached = cached_fetch();
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(body["state"], "cached");
    assert_eq!(body["installable"], false);
    assert_eq!(body["source"]["distribution"], "debian");
    assert_eq!(body["source"]["uri"], "https://example.org/debian");
    assert_eq!(body["source"]["suite"], "bookworm");
    assert_eq!(body["source"]["architecture"], "amd64");
    assert_eq!(
        body["source"]["configured_fingerprints"],
        serde_json::json!([fingerprint])
    );
    assert_eq!(
        body["artifact_sha256"],
        "0c190c47a57eaf9b339049983978ff0bec52a1d19576c679c40a366cba1d4bc6"
    );
    // The signed index fixture is intentionally not an extractable .deb.
    let invalid_store = dir.path().join("invalid-store");
    fs::create_dir(&invalid_store).unwrap();
    fs::set_permissions(&invalid_store, fs::Permissions::from_mode(0o700)).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args([
            "--json",
            "--config",
            config.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
            "--store-dir",
            invalid_store.to_str().unwrap(),
            "--max-age-seconds",
            "86400",
            "--allow-missing-valid-until",
            "fetch",
            "fixture",
            "--exact-version",
            "1.0-1",
            "--component",
            "main",
            "--publish-tree",
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!invalid_store.join("objects").exists());
    let lock_path = fs::read_dir(&cache_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().ends_with(".lock"))
        .unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let busy = cached_fetch();
    assert!(!busy.status.success());
    assert!(busy.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&busy.stderr).unwrap();
    assert_eq!(error["error"]["code"], "fetch_failed");
    drop(lock);
    fs::write(&blob, b"corrupt").unwrap();
    let bad_cached = cached_fetch();
    assert!(!bad_cached.status.success());
    assert!(bad_cached.stdout.is_empty());
    fs::write(&blob, fixture).unwrap();
    let index_path = fs::read_dir(&cache_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("index-")
        })
        .unwrap();
    let saved = fs::read(&index_path).unwrap();
    for tamper in ["index", "keyring"] {
        if tamper == "index" {
            fs::write(&index_path, b"corrupt").unwrap();
        } else {
            fs::write(&index_path, &saved).unwrap();
            fs::write(&keyring, b"forged keyring").unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .args([
                "--json",
                "--config",
                config.to_str().unwrap(),
                "--cache",
                cache_dir.to_str().unwrap(),
                "--max-age-seconds",
                "86400",
                "--allow-missing-valid-until",
                "fetch",
                "fixture",
                "--exact-version",
                "1.0-1",
                "--component",
                "main",
                "--max-bytes",
                "1024",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{tamper}");
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], "fetch_failed");
    }
}

#[test]
fn mutation_commands_fail_closed_without_running_input() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let marker = dir.path().join("should-not-exist");
    let payload = format!("$(touch {})", marker.display());
    {
        let args = ["gc", "--execute"];
        let output = Command::new(env!("CARGO_BIN_EXE_dich"))
            .arg("--json")
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let body: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(body["error"]["code"], "store_open_failed");
        assert!(!marker.exists());
    }
    let install = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "--max-age-seconds", "60", "install"])
        .arg(&payload)
        .output()
        .unwrap();
    assert!(!install.status.success());
    assert!(install.stdout.is_empty());
    assert!(!marker.exists());
    let install_error: serde_json::Value = serde_json::from_slice(&install.stderr).unwrap();
    assert_eq!(install_error["error"]["code"], "source_load_failed");

    let store_dir = dir.path().join("store");
    let remove = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "--store-dir"])
        .arg(&store_dir)
        .args(["remove", payload.as_str()])
        .output()
        .unwrap();
    assert!(!remove.status.success());
    assert!(remove.stdout.is_empty());
    let body: serde_json::Value = serde_json::from_slice(&remove.stderr).unwrap();
    assert_eq!(body["error"]["code"], "store_open_failed");
    assert!(!marker.exists());
}

#[test]
fn profile_list_reports_empty_initialized_store() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let store_dir = dir.path().join("store");
    fs::create_dir(&store_dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
    dich_store::MetadataDb::open(&store_dir).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "--store-dir"])
        .arg(&store_dir)
        .args(["profile", "list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["profiles"], serde_json::json!([]));
}
