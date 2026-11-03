# ADR 0027 — Shared-dependency integration boundary

Status: Proposed; the Phase 4 shared-dependency integration gate remains open.

## Context

The Phase 4 integration criterion requires two allowed versions sharing a dependency. ADR 0025 allows only one self-contained DSO per package and rejects all `NEEDED` entries. ADR 0026 selects direct explicit-path loading for that class and rejects a custom loader, wrapper, ambient loader paths, RUNPATH patching, and mount namespaces for broader packages. The current allowed class therefore cannot express the integration fixture requested by the roadmap.

## Evidence

On Ubuntu WSL and Debian 13 WSL, two unsigned local `.deb` fixtures containing one dependency-free DSO each were reported `supported` by `dich inspect --json`. Both unchanged DSO versions loaded by explicit path in both runtimes. These checks establish only the existing standalone fixture class. They do not test a shared dependency, repository signatures, store publication, installation, or activation. The Debian fixture used gzip; xz inspection invokes `/usr/bin/xz`, which is absent from this minimal WSL image.

## Decision needed

Before changing the allowlist, define and test a dependency-closure contract that answers how dependencies are resolved and loaded, how SONAME collisions and symbol interposition are prevented, and how ABI/version constraints are checked. Keep dependency-bearing packages `review_required` or `unsupported` until that contract has an end-to-end fixture across both distributions. Do not mark the shared-dependency roadmap item complete based on standalone fixtures.

