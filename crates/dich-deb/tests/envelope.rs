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
