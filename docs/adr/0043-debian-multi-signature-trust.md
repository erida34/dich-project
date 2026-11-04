# ADR 0043 — Explicit trust for Debian multi-signature Release metadata

Status: Accepted.

## Context

Debian Bookworm and Trixie Release metadata is currently signed by three keys: the Bookworm archive automatic key, the Trixie archive automatic key, and the matching suite release key. Dich intentionally rejects a signed Release if any reported signer is outside the configured fingerprint allowlist. The previous setup defaults pinned only one signer and selected suite-specific keyrings that omitted the other signatures, so `dich update` failed with `UntrustedSigner` or signature verification failure.

## Decision

Debian defaults use the complete distro-provided archive keyring and explicitly allow every current official signer for the selected suite:

- Bookworm: `B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8`, `04B54C3CDCA79751B16BC6B5225629DF75B188BD`, and `4D64FEC119C2029067D6E791F8D2585B8783D481`.
- Trixie: `B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8`, `04B54C3CDCA79751B16BC6B5225629DF75B188BD`, and `41587F7DB8C774BCCF131416762F67A0B2C39DE4`.

The Debian archive key list is verified against Debian's [official archive signing-key page](https://ftp-master.debian.org/keys.html). Current Bookworm and Trixie InRelease files were also cryptographically checked with Debian's `debian-archive-keyring` 2025.1 keyring; each produced exactly the three valid signatures above. Ubuntu defaults remain unchanged because their current supported Release files use the already pinned archive signer.

## Consequences

- Default policies continue to fail closed if any Release signature is invalid or signed by an unlisted key.
- The signing-key set and complete keyring are coupled; changes require rechecking official signer identities and both supported Debian suites.
- Existing `/etc/dich/sources.toml` files are never silently overwritten. Operators upgrading an old Debian setup must explicitly add the two missing signer fingerprints to the existing suite policy.
