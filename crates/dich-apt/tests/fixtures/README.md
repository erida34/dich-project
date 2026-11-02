# Repository signature test fixtures

`Release` is synthetic. The associated signature and public-key fixtures were generated solely for tests with GnuPG 2.4.4 and throwaway Ed25519 keys; no private key is included. `InRelease` and `Release.gpg` use the ordinary fixture key; `SubRelease.gpg` uses a signing subkey; the expired and revoked fixtures exercise those failures; `MultiRelease.gpg` has two signatures. Their fingerprints are recorded in `src/signature_tests.rs`. These keys do not establish trust in any real repository. `debian.sources` and `source-policy.toml` are syntax examples; the fingerprint in the TOML is synthetic.

The `index/` fixture has a separate throwaway signing key and synthetic SHA256 entries covering valid gzip/xz data, deliberately truncated streams, trailing junk and highly compressible oversized output. Its public fingerprint is recorded in `index_verification.rs`.

`control/base-files.control` is an excerpt of the Debian trixie `base-files` control record; `control/trixie-0ad.Packages` is the first record from the Debian trixie main amd64 Packages index cached on `dich-root`. They are parser fixtures, not authenticated inputs or installation advice.
