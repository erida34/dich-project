#![cfg(target_os = "linux")]
use crate::transport::{
    FetchError, HttpsTransport, NetworkResponse, Transport, fetch_with_transport, resolve_redirect,
};
use crate::{
    Distribution, FreshnessPolicy, IndexFormat, SourcePolicy, authorize_artifact, import_sources,
    select_indexed_artifact, validate_release, verify_configured_inrelease, verify_packages_index,
};
use std::{
    collections::VecDeque,
    fs,
    io::Read,
    time::{Duration, UNIX_EPOCH},
};
use url::Url;

#[test]
fn metadata_download_authenticates_and_checks_signed_index() {
    use crate::IndexLimits;
    use crate::transport::{fetch_index_with_transport, fetch_release_with_transport};
    let (_dir, authorized) = local_authorization("https://example.org/debian");
    let source = authorized.release().source();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let mut transport = Fake {
        responses: VecDeque::from([response(
            200,
            None,
            include_bytes!("../tests/fixtures/index/InRelease"),
        )]),
        calls: vec![],
    };
    let release = fetch_release_with_transport(source, &mut transport).unwrap();
    assert!(transport.calls[0].ends_with("/debian/dists/bookworm/InRelease"));
    let policy =
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap();
    let release = validate_release(&release, now, policy).unwrap();
    let mut index_transport = Fake {
        responses: VecDeque::from([response(
            200,
            None,
            include_bytes!("../tests/fixtures/index/Packages.gz"),
        )]),
        calls: vec![],
    };
    let index = fetch_index_with_transport(
        &release,
        "main",
        IndexFormat::Gzip,
        IndexLimits::default(),
        &mut index_transport,
        || now,
    )
    .unwrap();
    assert!(select_indexed_artifact(index.index(), "fixture", "1.0-1").is_ok());
    let mut forged = Fake {
        responses: VecDeque::from([response(200, None, b"not signed")]),
        calls: vec![],
    };
    assert!(fetch_release_with_transport(source, &mut forged).is_err());
    let mut redirect = Fake {
        responses: VecDeque::from([response(302, Some("https://evil.example/InRelease"), b"")]),
        calls: vec![],
    };
    assert!(fetch_release_with_transport(source, &mut redirect).is_err());
    assert_eq!(redirect.calls.len(), 1);
    let oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    let mut too_large = Fake {
        responses: VecDeque::from([response(200, None, &oversized)]),
        calls: vec![],
    };
    assert!(fetch_release_with_transport(source, &mut too_large).is_err());
    let mut corrupt = Fake {
        responses: VecDeque::from([response(200, None, b"bad index")]),
        calls: vec![],
    };
    assert!(
        fetch_index_with_transport(
            &release,
            "main",
            IndexFormat::Gzip,
            IndexLimits::default(),
            &mut corrupt,
            || now
        )
        .is_err()
    );
}

#[test]
fn missing_inrelease_uses_verified_detached_signature_only() {
    use crate::transport::fetch_release_with_transport;
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let key = dir.path().join("key.gpg");
    fs::write(
        &key,
        include_bytes!("../tests/fixtures/freshness/keyring.gpg"),
    )
    .unwrap();
    let path = key.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        path,
        &["F54741F2B0E1F1B32F7EE55EC9079FF55FECB8D2"],
    )
    .unwrap();
    let stanza = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {path}\n"
    );
    let source = import_sources(&stanza, &policy).unwrap().remove(0);
    let mut fallback = Fake {
        responses: VecDeque::from([
            response(404, None, b""),
            response(
                200,
                None,
                include_bytes!("../tests/fixtures/freshness/valid.Release"),
            ),
            response(
                200,
                None,
                include_bytes!("../tests/fixtures/freshness/valid.Release.gpg"),
            ),
        ]),
        calls: vec![],
    };
    assert!(fetch_release_with_transport(&source, &mut fallback).is_ok());
    assert_eq!(fallback.calls.len(), 3);
    let mut bad_signature = Fake {
        responses: VecDeque::from([
            response(404, None, b""),
            response(
                200,
                None,
                include_bytes!("../tests/fixtures/freshness/valid.Release"),
            ),
            response(200, None, b"bad signature"),
        ]),
        calls: vec![],
    };
    assert!(fetch_release_with_transport(&source, &mut bad_signature).is_err());
    let mut forged = Fake {
        responses: VecDeque::from([
            response(200, None, b"forged"),
            response(
                200,
                None,
                include_bytes!("../tests/fixtures/freshness/valid.Release"),
            ),
        ]),
        calls: vec![],
    };
    assert!(fetch_release_with_transport(&source, &mut forged).is_err());
    assert_eq!(forged.calls.len(), 1);
    let mut unavailable = Fake {
        responses: VecDeque::from([response(500, None, b"")]),
        calls: vec![],
    };
    assert!(fetch_release_with_transport(&source, &mut unavailable).is_err());
    assert_eq!(unavailable.calls.len(), 1);
}

#[test]
fn update_authenticates_fetches_and_caches_signed_index() {
    use crate::update::update_with_transport;
    use crate::{IndexLimits, SnapshotJournal};
    let (dir, authorized) = local_authorization("https://example.org/debian");
    let source = authorized.release().source();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let policy =
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap();
    let journal = SnapshotJournal::open(dir.path()).unwrap();
    let mut transport = Fake {
        responses: VecDeque::from([
            response(
                200,
                None,
                include_bytes!("../tests/fixtures/index/InRelease"),
            ),
            response(
                200,
                None,
                include_bytes!("../tests/fixtures/index/Packages.xz"),
            ),
        ]),
        calls: vec![],
    };
    let result = update_with_transport(
        source,
        &journal,
        policy,
        IndexLimits::default(),
        &mut transport,
        || now,
    )
    .unwrap();
    assert_eq!(result.indices, 1);
    let (_, index) = journal
        .load_index_at(
            source,
            policy,
            "main",
            IndexFormat::Xz,
            IndexLimits::default(),
            now,
        )
        .unwrap();
    assert!(select_indexed_artifact(&index, "fixture", "1.0-1").is_ok());
    let found = crate::query::query_with_clock(
        std::slice::from_ref(source),
        &journal,
        policy,
        crate::query::Query::Search("fix"),
        || now,
    )
    .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "fixture");
    let versions = crate::query::query_with_clock(
        std::slice::from_ref(source),
        &journal,
        policy,
        crate::query::Query::Versions("fixture"),
        || now,
    )
    .unwrap();
    assert_eq!(versions[0].version, "1.0-1");
    assert!(
        crate::query::query_with_clock(
            std::slice::from_ref(source),
            &journal,
            policy,
            crate::query::Query::Show("missing"),
            || now
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        crate::query::query_with_clock(
            std::slice::from_ref(source),
            &journal,
            policy,
            crate::query::Query::Search("../"),
            || now
        )
        .is_err()
    );
    assert!(
        crate::query::query_with_clock(
            std::slice::from_ref(source),
            &journal,
            policy,
            crate::query::Query::Search("fix"),
            || now + Duration::from_secs(3 * 86400)
        )
        .is_err()
    );
    let index_name = crate::cache::index_name(
        source,
        authorized.release().release().contents(),
        "main",
        IndexFormat::Xz,
    )
    .unwrap();
    fs::write(dir.path().join(index_name), b"corrupt").unwrap();
    assert!(
        crate::query::query_with_clock(
            std::slice::from_ref(source),
            &journal,
            policy,
            crate::query::Query::Search("fix"),
            || now
        )
        .is_err()
    );
}

#[test]
fn redirect_policy_rejects_origin_escape_and_encoded_paths() {
    let base = Url::parse("https://example.org/debian/").unwrap();
    let current = base.join("pool/a.deb").unwrap();
    for location in [
        "http://example.org/debian/pool/a.deb",
        "https://evil.example/debian/pool/a.deb",
        "https://example.org:444/debian/a.deb",
        "//evil.example/a.deb",
        "/outside/a.deb",
        "/debian/%2e%2e/a.deb",
        "/debian/a.deb?token=1",
        "https://user@example.org/debian/a.deb",
        "../outside/a.deb",
    ] {
        assert!(
            resolve_redirect(&base, &current, location).is_err(),
            "accepted {location}"
        );
    }
    assert!(resolve_redirect(&base, &current, "/debian/pool/mirror/a.deb").is_ok());
}

struct Fake {
    responses: VecDeque<NetworkResponse>,
    calls: Vec<String>,
}
impl Transport for Fake {
    fn request(&mut self, url: &Url, _: Duration) -> Result<NetworkResponse, FetchError> {
        self.calls.push(url.to_string());
        self.responses.pop_front().ok_or(FetchError::Transport)
    }
}
fn response(status: u16, location: Option<&str>, body: &[u8]) -> NetworkResponse {
    NetworkResponse {
        status,
        location: location.map(str::to_owned),
        content_length: None,
        content_encoding: None,
        body: Box::new(std::io::Cursor::new(body.to_vec())),
    }
}

#[test]
fn fetch_streams_only_verified_bytes_and_follows_permitted_redirects() {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let key = dir.path().join("key.gpg");
    fs::write(&key, include_bytes!("../tests/fixtures/index/keyring.gpg")).unwrap();
    let path = key.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://example.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        path,
        &["9DDAB0BA30893BBE88A2E583BBBAC55DCA1F9AA8"],
    )
    .unwrap();
    let stanza = format!(
        "Types: deb\nURIs: https://example.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: {path}\n"
    );
    let source = import_sources(&stanza, &policy).unwrap().remove(0);
    let release =
        verify_configured_inrelease(&source, include_bytes!("../tests/fixtures/index/InRelease"))
            .unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let fresh = validate_release(
        &release,
        now,
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap(),
    )
    .unwrap();
    let index = verify_packages_index(
        &release,
        "main",
        IndexFormat::Gzip,
        include_bytes!("../tests/fixtures/index/Packages.gz"),
    )
    .unwrap();
    let metadata = select_indexed_artifact(&index, "fixture", "1.0-1").unwrap();
    let authorized = authorize_artifact(&fresh, &metadata, now).unwrap();
    let body = include_bytes!("../tests/fixtures/index/fixture.deb");
    let mut transport = Fake {
        responses: VecDeque::from([
            response(302, Some("/debian/pool/mirror/fixture.deb"), b""),
            response(200, None, body),
        ]),
        calls: vec![],
    };
    let mut verified = fetch_with_transport(&authorized, 1024, &mut transport, || now).unwrap();
    let mut bytes = Vec::new();
    verified.read_to_end(&mut bytes).unwrap();
    assert_eq!(&bytes, body);
    assert_eq!(transport.calls.len(), 2);
    let mut evil = Fake {
        responses: VecDeque::from([response(302, Some("https://evil.example/steal"), b"")]),
        calls: vec![],
    };
    assert!(fetch_with_transport(&authorized, 1024, &mut evil, || now).is_err());
    assert_eq!(evil.calls.len(), 1);
    let mut corrupt = Fake {
        responses: VecDeque::from([response(200, None, b"bad")]),
        calls: vec![],
    };
    assert!(fetch_with_transport(&authorized, 1024, &mut corrupt, || now).is_err());
}

fn local_authorization(uri: &str) -> (tempfile::TempDir, crate::AuthorizedArtifact) {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    let key = dir.path().join("key.gpg");
    fs::write(&key, include_bytes!("../tests/fixtures/index/keyring.gpg")).unwrap();
    let path = key.to_str().unwrap();
    let policy = SourcePolicy::new(
        Distribution::Debian,
        uri,
        "bookworm",
        &["main"],
        "amd64",
        path,
        &["9DDAB0BA30893BBE88A2E583BBBAC55DCA1F9AA8"],
    )
    .unwrap();
    let stanza =
        format!("Types: deb\nURIs: {uri}\nSuites: bookworm\nComponents: main\nSigned-By: {path}\n");
    let source = import_sources(&stanza, &policy).unwrap().remove(0);
    let release =
        verify_configured_inrelease(&source, include_bytes!("../tests/fixtures/index/InRelease"))
            .unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let fresh = validate_release(
        &release,
        now,
        FreshnessPolicy::new(Duration::from_secs(2 * 86400), Duration::ZERO, true).unwrap(),
    )
    .unwrap();
    let index = verify_packages_index(
        &release,
        "main",
        IndexFormat::Gzip,
        include_bytes!("../tests/fixtures/index/Packages.gz"),
    )
    .unwrap();
    let metadata = select_indexed_artifact(&index, "fixture", "1.0-1").unwrap();
    (dir, authorize_artifact(&fresh, &metadata, now).unwrap())
}

#[test]
fn fetch_rejects_bad_headers_loops_limits_and_expired_authorization() {
    let (_dir, authorized) = local_authorization("https://example.org/debian");
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let body = include_bytes!("../tests/fixtures/index/fixture.deb");
    let mut bad_length = response(200, None, body);
    bad_length.content_length = Some(1);
    let mut bad_encoding = response(200, None, body);
    bad_encoding.content_encoding = Some("gzip".into());
    for r in [
        bad_length,
        bad_encoding,
        response(206, None, body),
        response(404, None, body),
    ] {
        let mut transport = Fake {
            responses: VecDeque::from([r]),
            calls: vec![],
        };
        assert!(fetch_with_transport(&authorized, 1024, &mut transport, || now).is_err());
    }
    let mut loops = Fake {
        responses: (0..6)
            .map(|_| response(302, Some("/debian/pool/a.deb"), b""))
            .collect(),
        calls: vec![],
    };
    assert!(fetch_with_transport(&authorized, 1024, &mut loops, || now).is_err());
    assert_eq!(loops.calls.len(), 6);
    let mut no_network = Fake {
        responses: VecDeque::new(),
        calls: vec![],
    };
    assert!(fetch_with_transport(&authorized, 1, &mut no_network, || now).is_err());
    assert!(
        fetch_with_transport(&authorized, 1024, &mut no_network, || now
            + Duration::from_secs(3 * 86400))
        .is_err()
    );
    assert!(no_network.calls.is_empty());
}

fn tls_server() -> (u16, std::thread::JoinHandle<()>) {
    use rustls::{
        ServerConfig, ServerConnection, StreamOwned,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use std::{io::Write, net::TcpListener, sync::Arc};
    let cert = CertificateDer::from(include_bytes!("../tests/fixtures/tls/cert.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("../tests/fixtures/tls/key.der").to_vec(),
    ));
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut stream = StreamOwned::new(ServerConnection::new(config).unwrap(), socket);
        let mut request = Vec::new();
        let mut byte = [0];
        while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => request.push(byte[0]),
                _ => return,
            }
        }
        let body = include_bytes!("../tests/fixtures/index/fixture.deb");
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    });
    (port, handle)
}

#[test]
fn actual_https_checks_certificate_and_verifies_artifact() {
    use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
    use std::sync::Arc;
    let (port, server) = tls_server();
    let (_dir, authorized) = local_authorization(&format!("https://localhost:{port}/debian"));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            include_bytes!("../tests/fixtures/tls/ca.der").to_vec(),
        ))
        .unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .redirects(0)
        .try_proxy_from_env(false)
        .tls_config(Arc::new(config))
        .build();
    let mut transport = HttpsTransport { agent };
    let now = UNIX_EPOCH + Duration::from_secs(1_793_707_200);
    let mut verified = fetch_with_transport(&authorized, 1024, &mut transport, || now).unwrap();
    let mut body = Vec::new();
    verified.read_to_end(&mut body).unwrap();
    assert_eq!(body, include_bytes!("../tests/fixtures/index/fixture.deb"));
    server.join().unwrap();

    let (port, server) = tls_server();
    let (_dir, authorized) = local_authorization(&format!("https://localhost:{port}/debian"));
    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .redirects(0)
        .try_proxy_from_env(false)
        .build();
    let mut transport = HttpsTransport { agent };
    assert!(fetch_with_transport(&authorized, 1024, &mut transport, || now).is_err());
    server.join().unwrap();
}
