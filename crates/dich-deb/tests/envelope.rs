use dich_deb::{Limits, inspect_deb};
use std::io::Cursor;

fn tar_with_file(path: &str, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut output);
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, data).unwrap();
        tar.finish().unwrap();
    }
    output
}
fn deb(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut builder = ar::Builder::new(&mut bytes);
        for (name, content) in members {
            let header = ar::Header::new(name.as_bytes().to_vec(), content.len() as u64);
            builder.append(&header, Cursor::new(content)).unwrap();
        }
    }
    bytes
}
#[test]
fn reads_common_debian_envelope_and_both_tar_streams() {
    let control = tar_with_file("control", b"Package: sample\nVersion: 1\n");
    let data = tar_with_file("usr/share/sample.txt", b"hello");
    let bytes = deb(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &control),
        ("data.tar", &data),
    ]);
    let report = inspect_deb(&bytes, Limits::default()).unwrap();
    assert_eq!(report.control_entries, 1);
    assert_eq!(report.data_entries, 1);
    assert_eq!(report.data_file_bytes, 5);
}
#[test]
fn rejects_wrong_order_duplicate_members_truncation_and_size_limits() {
    let control = tar_with_file("control", b"metadata");
    let data = tar_with_file("file", b"hello");
    for bytes in [
        deb(&[
            ("data.tar", &data),
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
        ]),
        deb(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            ("control.tar", &control),
            ("data.tar", &data),
        ]),
        deb(&[
            ("debian-binary", b"3.0\n"),
            ("control.tar", &control),
            ("data.tar", &data),
        ]),
    ] {
        assert!(inspect_deb(&bytes, Limits::default()).is_err());
    }
    let mut bytes = deb(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &control),
        ("data.tar", &data),
    ]);
    bytes.truncate(bytes.len() - 100);
    assert!(inspect_deb(&bytes, Limits::default()).is_err());
    let small = Limits {
        max_archive_bytes: 16,
        ..Limits::default()
    };
    assert!(inspect_deb(&bytes, small).is_err());
}

#[test]
fn control_archive_requires_exactly_one_regular_control_file() {
    let empty = {
        let mut out = Vec::new();
        {
            let mut t = tar::Builder::new(&mut out);
            t.finish().unwrap();
        }
        out
    };
    let data = tar_with_file("file", b"hello");
    let bytes = deb(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &empty),
        ("data.tar", &data),
    ]);
    assert!(inspect_deb(&bytes, Limits::default()).is_err());
}

#[test]
fn rejects_huge_ar_lengths_before_archive_parser_allocation() {
    let mut bytes = b"!<arch>\n".to_vec();
    let mut header = [b' '; 60];
    header[..2].copy_from_slice(b"//");
    header[48..58].copy_from_slice(b"9999999999");
    header[58..].copy_from_slice(b"`\n");
    bytes.extend_from_slice(&header);
    assert!(inspect_deb(&bytes, Limits::default()).is_err());
}

#[test]
fn rejects_limits_on_entry_count_file_size_and_path_depth() {
    let control = tar_with_file("control", b"metadata");
    let data = tar_with_file("usr/share/file", b"hello");
    let bytes = deb(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &control),
        ("data.tar", &data),
    ]);
    for limits in [
        Limits {
            max_entries: 1,
            ..Limits::default()
        },
        Limits {
            max_file_bytes: 4,
            ..Limits::default()
        },
        Limits {
            max_total_file_bytes: 9,
            ..Limits::default()
        },
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
    ] {
        assert!(inspect_deb(&bytes, limits).is_err());
    }
}

#[cfg(target_os = "linux")]
fn compress(program: &str, bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    output.stdout
}

#[test]
#[cfg(target_os = "linux")]
fn reads_gzip_xz_and_zstd_members_with_limits() {
    let control = tar_with_file("control", b"Package: sample\nVersion: 1\n");
    let data = tar_with_file("usr/share/sample", b"hello");
    for (program, control_name, data_name) in [
        ("/usr/bin/gzip", "control.tar.gz", "data.tar.gz"),
        ("/usr/bin/xz", "control.tar.xz", "data.tar.xz"),
        ("/usr/bin/zstd", "control.tar.zst", "data.tar.zst"),
    ] {
        let control_compressed = compress(program, &control);
        let data_compressed = compress(program, &data);
        let bytes = deb(&[
            ("debian-binary", b"2.0\n"),
            (control_name, &control_compressed),
            (data_name, &data_compressed),
        ]);
        assert_eq!(
            inspect_deb(&bytes, Limits::default())
                .unwrap_or_else(|e| panic!("{program}: {e}"))
                .data_file_bytes,
            5
        );
        let too_small = Limits {
            max_expanded_tar_bytes: 512,
            ..Limits::default()
        };
        assert!(inspect_deb(&bytes, too_small).is_err());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn rejects_corrupt_truncated_and_overexpanding_compressed_members() {
    let control = tar_with_file("control", b"Package: sample\nVersion: 1\n");
    let bomb = tar_with_file("large", &vec![0; 1024 * 1024]);
    for (program, data_name) in [
        ("/usr/bin/gzip", "data.tar.gz"),
        ("/usr/bin/xz", "data.tar.xz"),
        ("/usr/bin/zstd", "data.tar.zst"),
    ] {
        let compressed = compress(program, &bomb);
        let bytes = deb(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            (data_name, &compressed),
        ]);
        let limits = Limits {
            max_expanded_tar_bytes: 65536,
            ..Limits::default()
        };
        assert!(
            inspect_deb(&bytes, limits).is_err(),
            "bomb accepted: {program}"
        );
        let truncated = &compressed[..compressed.len() - 3];
        let bytes = deb(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            (data_name, truncated),
        ]);
        assert!(
            inspect_deb(&bytes, Limits::default()).is_err(),
            "truncation accepted: {program}"
        );
    }
}

#[test]
#[ignore = "requires the hash-checked Ubuntu noble alsa-topology-conf sample"]
fn inspects_real_ubuntu_noble_sample() {
    let path = std::env::var("DICH_DEB_SAMPLE").unwrap();
    let bytes = std::fs::read(path).unwrap();
    let report = inspect_deb(&bytes, Limits::default()).unwrap();
    assert!(report.control_entries >= 1);
    assert!(report.data_entries >= 1);
    assert!(report.data_file_bytes > 0);
}

#[test]
#[cfg(target_os = "linux")]
fn rejects_concatenated_compressed_archives_and_trailing_tar_content() {
    let control = tar_with_file("control", b"metadata");
    let data = tar_with_file("first", b"one");
    let extra = tar_with_file("second", b"two");
    for (program, data_name) in [
        ("/usr/bin/gzip", "data.tar.gz"),
        ("/usr/bin/xz", "data.tar.xz"),
        ("/usr/bin/zstd", "data.tar.zst"),
    ] {
        let mut compressed = compress(program, &data);
        compressed.extend_from_slice(&compress(program, &extra));
        let bytes = deb(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            (data_name, &compressed),
        ]);
        assert!(
            inspect_deb(&bytes, Limits::default()).is_err(),
            "concatenated stream accepted: {program}"
        );
    }
}

#[test]
fn file_count_limit_applies_across_control_and_data() {
    let control = tar_with_file("control", b"metadata");
    let data = tar_with_file("file", b"hello");
    let bytes = deb(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &control),
        ("data.tar", &data),
    ]);
    let limits = Limits {
        max_files: 1,
        ..Limits::default()
    };
    assert!(inspect_deb(&bytes, limits).is_err());
}
fn raw_tar(path: &[u8], mode: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..path.len()].copy_from_slice(path);
        header.set_size(1);
        header.set_mode(mode);
        header.set_cksum();
        builder.append(&header, &b"x"[..]).unwrap();
        builder.finish().unwrap();
    }
    out
}
#[test]
fn rejects_traversal_absolute_paths_and_dangerous_mode_bits() {
    let control = tar_with_file("control", b"metadata");
    for (path, mode) in [
        (b"../escape".as_slice(), 0o644),
        (b"/etc/evil".as_slice(), 0o644),
        (b"usr/../../escape".as_slice(), 0o644),
        (b"usr/bin/suid".as_slice(), 0o4755),
    ] {
        let data = raw_tar(path, mode);
        let bytes = deb(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            ("data.tar", &data),
        ]);
        assert!(
            inspect_deb(&bytes, Limits::default()).is_err(),
            "accepted {:?}",
            path
        );
    }
}

fn raw_entries(entries: &[(&[u8], tar::EntryType)]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        for (path, kind) in entries {
            let mut header = tar::Header::new_gnu();
            header.as_mut_bytes()[..path.len()].copy_from_slice(path);
            header.set_entry_type(*kind);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, &[][..]).unwrap();
        }
        builder.finish().unwrap();
    }
    out
}
#[test]
fn rejects_links_devices_extensions_and_ambiguous_paths() {
    let control = tar_with_file("control", b"metadata");
    for kind in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::Char,
        tar::EntryType::Block,
        tar::EntryType::Fifo,
        tar::EntryType::XHeader,
    ] {
        let data = raw_entries(&[(b"bad", kind)]);
        let bytes = deb(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            ("data.tar", &data),
        ]);
        assert!(
            inspect_deb(&bytes, Limits::default()).is_err(),
            "accepted {kind:?}"
        );
    }
    for entries in [
        vec![
            (b"same".as_slice(), tar::EntryType::Regular),
            (b"./same".as_slice(), tar::EntryType::Regular),
        ],
        vec![
            (b"dir/file".as_slice(), tar::EntryType::Regular),
            (b"dir".as_slice(), tar::EntryType::Regular),
        ],
        vec![
            (b"dir".as_slice(), tar::EntryType::Regular),
            (b"dir/file".as_slice(), tar::EntryType::Regular),
        ],
    ] {
        let data = raw_entries(&entries);
        let bytes = deb(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control),
            ("data.tar", &data),
        ]);
        assert!(inspect_deb(&bytes, Limits::default()).is_err());
    }
}
