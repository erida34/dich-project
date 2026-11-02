# ADR 0001 — Scope and system integration

Status: Accepted for initial implementation.

Decision: Dich manages a separate package store populated from verified APT repositories. It does not override apt/dpkg and does not claim arbitrary Debian packages are relocatable. First supported repository is a single Debian/Ubuntu suite and architecture at a time. Initial compatible class is explicitly allowlisted relocatable library-only packages.

Consequences: Easier coexistence with host tools; more work on ELF, loader paths, ABI, script and service assumptions; conservative errors are expected. Cross-suite, rootless vs daemon, store path, dependency solver implementation and relocation technique each require follow-up ADRs.
