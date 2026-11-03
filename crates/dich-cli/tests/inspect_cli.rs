#![cfg(target_os = "linux")]
use std::{fs, os::unix::fs::symlink, process::Command};
fn run(path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dich"))
        .args(["--json", "inspect", path.to_str().unwrap()])
        .output()
        .unwrap()
}
fn tar_file(path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut output);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
        builder.finish().unwrap();
    }
    output
}
fn deb() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut b = ar::Builder::new(&mut bytes);
        for (name, body) in [
            ("debian-binary", b"2.0\n".to_vec()),
            (
                "control.tar",
                tar_file(
                    "control",
                    b"Package: sample\nVersion: 1\nArchitecture: all\n",
                ),
            ),
            ("data.tar", tar_file("usr/share/example", b"data")),
        ] {
            let header = ar::Header::new(name.as_bytes().to_vec(), body.len() as u64);
            b.append(&header, body.as_slice()).unwrap();
        }
    }
    bytes
}
#[test]
fn reports_untrusted_archive_without_running_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.deb");
    fs::write(&path, deb()).unwrap();
    let out = run(&path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["status"], "completed");
    assert_eq!(body["trust"], "unverified");
    assert_eq!(body["installable"], false);
    assert_eq!(body["data_files"], 1);
    assert_eq!(body["compatibility_report"]["schema_version"], 1);
    assert_eq!(body["compatibility_report"]["status"], "review_required");
    assert!(body["compatibility_report"]["evidence"].is_array());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn supported_compatibility_does_not_claim_authenticity_or_installability() {
    let dir = tempfile::tempdir().unwrap();
    let control = tar_file("control", b"Package: dich-fixture\nVersion: 1\n");
    let data = tar_file(
        "usr/lib/x86_64-linux-gnu/libdich-fixture.so",
        include_bytes!("../../dich-elf/tests/fixtures/libdich-fixture.so"),
    );
    let mut archive = Vec::new();
    {
        let mut builder = ar::Builder::new(&mut archive);
        for (name, body) in [
            ("debian-binary", b"2.0\n".as_slice()),
            ("control.tar", control.as_slice()),
            ("data.tar", data.as_slice()),
        ] {
            let header = ar::Header::new(name.as_bytes().to_vec(), body.len() as u64);
            builder.append(&header, body).unwrap();
        }
    }
    let path = dir.path().join("pure-library.deb");
    fs::write(&path, archive).unwrap();
    let out = run(&path);
    assert!(out.status.success());
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["trust"], "unverified");
    assert_eq!(body["installable"], false);
    assert_eq!(body["compatibility_report"]["status"], "supported");
}
#[test]
fn refuses_symlinks_fifos_oversized_and_malformed_files() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("bad.deb");
    fs::write(&file, b"not a deb").unwrap();
    assert!(!run(&file).status.success());
    let link = dir.path().join("link");
    symlink(&file, &link).unwrap();
    assert!(!run(&link).status.success());
    let fifo = dir.path().join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(!run(&fifo).status.success());
    let big = dir.path().join("big");
    fs::File::create(&big)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    assert!(!run(&big).status.success());
}

#[test]
fn inspection_reports_but_never_runs_maintainer_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("executed");
    let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
    let mut control = Vec::new();
    {
        let mut b = tar::Builder::new(&mut control);
        for (path, body) in [
            (
                "control",
                b"Package: sample\nVersion: 1\nArchitecture: all\n".as_slice(),
            ),
            ("postinst", script.as_bytes()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, path, body).unwrap();
        }
        b.finish().unwrap();
    }
    let mut archive = Vec::new();
    {
        let mut b = ar::Builder::new(&mut archive);
        for (name, body) in [
            ("debian-binary", b"2.0\n".to_vec()),
            ("control.tar", control),
            ("data.tar", tar_file("usr/share/example", b"data")),
        ] {
            let h = ar::Header::new(name.as_bytes().to_vec(), body.len() as u64);
            b.append(&h, body.as_slice()).unwrap();
        }
    }
    let path = dir.path().join("scripts.deb");
    fs::write(&path, archive).unwrap();
    let out = run(&path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["scripts"][0]["name"], "postinst");
    assert_eq!(body["compatibility_report"]["status"], "unsupported");
    assert!(!marker.exists());
}
#[test]
fn inspection_rejects_symlinked_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("fixture.deb"), deb()).unwrap();
    let link = dir.path().join("linked");
    symlink(&real, &link).unwrap();
    let out = run(&link.join("fixture.deb"));
    assert!(!out.status.success());
}
