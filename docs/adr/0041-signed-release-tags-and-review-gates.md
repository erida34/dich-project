# ADR 0041: Signed release tags and review gates

- Status: accepted
- Date: 2026-11-04
- Decision owners: Dich maintainers

## Context

The experimental `v0.7.0` tag is annotated but unsigned. GitHub build provenance identifies the workflow and source revision; it does not prove that the release tag was authorized by Dich's maintainer. The repository also had no protected default branch or required review gate. A production release must fail closed when signer identity or reviewed source controls are missing.

## Decision

- Require a signed annotated release tag. CI imports exactly one public primary key from repository variable `DICH_RELEASE_SIGNING_PUBLIC_KEY`, verifies its full primary fingerprint equals `DICH_RELEASE_SIGNING_FINGERPRINT`, then runs `git verify-tag` before building.
- Keep the private signing key outside GitHub Actions. Maintainers sign tags locally; CI receives only the public key and expected fingerprint.
- Protect `master` with an active GitHub ruleset requiring a pull request, one approval, approval after the most recent push, resolved review threads, and passing `rust` and `deb-package-smoke` contexts. Configure no bypass actor.
- Protect `v*` tags through a separate active ruleset. The repository owner remains its bypass actor because the repository must be initially administered by that owner.
- Do not represent GitHub artifact provenance as a package signature.

## Consequences

The release workflow intentionally fails until the signer variables are configured and an actually signed tag is pushed. The branch rule prevents direct master pushes and requires another eligible reviewer; a solo maintainer cannot satisfy it alone. The version-tag owner bypass and repository-variable administration remain owner-account trust boundaries. `v0.7.0` remains an unsigned experimental prerelease and is not retroactively trusted.

## Verification

GitHub API confirmed active repository rulesets `Protect master` (ID 26489917) and `Protect version tags` (ID 26488874). The master ruleset has no bypass actors and currently requires the exact CI status contexts. A WSL fixture generated a temporary Ed25519 key and verified that a signed test tag passes while an unsigned tag and mismatched fingerprint fail. Production verification against the maintainer's key remains unverified because no trusted key is configured.
