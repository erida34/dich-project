#![cfg(target_os = "linux")]
use crate::signatures::{verify_detached_release, verify_inrelease};
use crate::{Distribution, Source, SourcePolicy, import_sources};

const KEY: &str = "A85557F5D19615DCBE48C0A673D4B958454DE07D";
const RELEASE: &[u8] = include_bytes!("../tests/fixtures/Release");
const SIGNATURE: &[u8] = include_bytes!("../tests/fixtures/Release.gpg");
const INRELEASE: &[u8] = include_bytes!("../tests/fixtures/InRelease");
const KEYRING: &[u8] = include_bytes!("../tests/fixtures/fixture-keyring.gpg");

fn source(fingerprint: &str) -> Source {
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://deb.debian.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        "/etc/dich/test.gpg",
        &[fingerprint],
    )
    .unwrap();
    let input = "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: /etc/dich/test.gpg\n";
    import_sources(input, &policy).unwrap().remove(0)
}

#[test]
fn verifies_clearsigned_and_detached_fixture() {
    let source = source(KEY);
    let clear = verify_inrelease(&source, KEYRING, INRELEASE).unwrap();
    assert_eq!(clear.contents(), RELEASE);
    assert_eq!(clear.signing_fingerprint(), KEY);
    let detached = verify_detached_release(&source, KEYRING, RELEASE, SIGNATURE).unwrap();
    assert_eq!(detached.contents(), RELEASE);
    assert_eq!(detached.signing_fingerprint(), KEY);
}

#[test]
fn rejects_untrusted_signer_tampering_and_missing_trust() {
    let other = source("1111111111111111111111111111111111111111");
    let source = source(KEY);
    assert!(verify_inrelease(&other, KEYRING, INRELEASE).is_err());
    assert!(verify_detached_release(&other, KEYRING, RELEASE, SIGNATURE).is_err());
    assert!(verify_inrelease(&source, b"", INRELEASE).is_err());
    assert!(
        verify_inrelease(
            &source,
            include_bytes!("../tests/fixtures/subkey-keyring.gpg"),
            INRELEASE
        )
        .is_err()
    );
    assert!(verify_detached_release(&source, KEYRING, b"Origin: forged\n", SIGNATURE).is_err());
    let mut tampered = INRELEASE.to_vec();
    let position = tampered.windows(7).position(|s| s == b"Fixture").unwrap();
    tampered[position] = b'X';
    assert!(verify_inrelease(&source, KEYRING, &tampered).is_err());
}

#[test]
fn rejects_unsigned_or_ambiguous_cleartext_and_oversized_inputs() {
    let source = source(KEY);
    assert!(verify_inrelease(&source, KEYRING, RELEASE).is_err());
    assert!(
        verify_inrelease(
            &source,
            KEYRING,
            &[INRELEASE, b"\nunsigned trailing data\n"].concat()
        )
        .is_err()
    );
    assert!(
        verify_inrelease(
            &source,
            KEYRING,
            &[b"unsigned prefix\n", INRELEASE].concat()
        )
        .is_err()
    );
    assert!(verify_inrelease(&source, KEYRING, &vec![b'x'; 4 * 1024 * 1024 + 1]).is_err());
    assert!(verify_detached_release(&source, KEYRING, RELEASE, &SIGNATURE[..10]).is_err());
}

#[test]
fn subkeys_are_bound_to_the_primary_and_bang_requires_exact_signer() {
    const PRIMARY: &str = "404BE4D2E49FD3618B3E35F3E92C7A9046F5C2A4";
    const SUBKEY: &str = "A473D2FC5A7194D926EB9954F3E200A4A97139F4";
    let keyring = include_bytes!("../tests/fixtures/subkey-keyring.gpg");
    let signature = include_bytes!("../tests/fixtures/SubRelease.gpg");
    assert_eq!(
        verify_detached_release(&source(PRIMARY), keyring, RELEASE, signature)
            .unwrap()
            .signing_fingerprint(),
        SUBKEY
    );
    assert!(
        verify_detached_release(&source(&format!("{PRIMARY}!")), keyring, RELEASE, signature)
            .is_err()
    );
    assert!(
        verify_detached_release(&source(&format!("{SUBKEY}!")), keyring, RELEASE, signature)
            .is_ok()
    );
}

#[test]
fn expired_and_revoked_keys_fail_closed() {
    let expired = source("37238D69E4D2234BA65374DB59B2B4D17BBB314F");
    assert!(
        verify_detached_release(
            &expired,
            include_bytes!("../tests/fixtures/expired-keyring.gpg"),
            RELEASE,
            include_bytes!("../tests/fixtures/ExpiredRelease.gpg")
        )
        .is_err()
    );
    let revoked = source("39CF31D274042EDE35B4161FE72FD244BD69F74E");
    assert!(
        verify_detached_release(
            &revoked,
            include_bytes!("../tests/fixtures/revoked-keyring.gpg"),
            RELEASE,
            include_bytes!("../tests/fixtures/RevokedRelease.gpg")
        )
        .is_err()
    );
}

#[test]
fn rejects_multiple_signatures_instead_of_choosing_an_ambiguous_result() {
    let trusted = source("0E9EAD0C974F7C3A3ABD1C0C9E5699515F5745A0");
    assert!(
        verify_detached_release(
            &trusted,
            include_bytes!("../tests/fixtures/multiple-keyring.gpg"),
            RELEASE,
            include_bytes!("../tests/fixtures/MultiRelease.gpg")
        )
        .is_err()
    );
}

#[test]
fn accepts_multiple_signatures_only_when_all_signers_are_authorized() {
    let policy = SourcePolicy::new(
        Distribution::Debian,
        "https://deb.debian.org/debian",
        "bookworm",
        &["main"],
        "amd64",
        "/etc/dich/test.gpg",
        &[
            "0E9EAD0C974F7C3A3ABD1C0C9E5699515F5745A0",
            "432AAFF25D89B513E5B512B599D2063872768B03",
        ],
    )
    .unwrap();
    let input = "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: /etc/dich/test.gpg\n";
    let source = import_sources(input, &policy).unwrap().remove(0);
    let verified = verify_detached_release(
        &source,
        include_bytes!("../tests/fixtures/multiple-keyring.gpg"),
        RELEASE,
        include_bytes!("../tests/fixtures/MultiRelease.gpg"),
    )
    .unwrap();
    assert_eq!(verified.signing_fingerprints().len(), 2);
}

#[test]
#[ignore = "requires Ubuntu noble cached InRelease and archive keyring on the host"]
fn ubuntu_noble_cached_repository_signature() {
    let policy = SourcePolicy::new(
        Distribution::Ubuntu,
        "https://archive.ubuntu.com/ubuntu",
        "noble",
        &["main"],
        "amd64",
        "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        &["F6ECB3762474EDA9D21B7022871920D1991BC93C"],
    )
    .unwrap();
    let stanza = "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\nSuites: noble\nComponents: main\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n";
    let source = import_sources(stanza, &policy).unwrap().remove(0);
    let keyring = std::fs::read(source.keyring()).unwrap();
    let input = std::fs::read("/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble_InRelease")
        .unwrap();
    let verified = verify_inrelease(&source, &keyring, &input).unwrap();
    assert!(
        verified
            .contents()
            .windows(b"Suite: noble".len())
            .any(|window| window == b"Suite: noble")
    );
}
