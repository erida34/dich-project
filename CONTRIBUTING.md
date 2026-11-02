# Contributing

Read `AGENTS.md` and `ROADMAP.md`. Propose changes via issues/PRs, write tests first for behavior/security-sensitive changes, keep documentation and Clap-generated man/completions in sync, and never bypass repository authentication. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets` before submitting. Use conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Significant design decisions require an ADR.

## Coding guidelines

- Keep package-management logic in the owning library crate, not the CLI. Document data models and trust invariants before implementing a phase.
- Treat repository metadata, archive contents and paths as hostile. Use bounded inputs, typed errors and structured process arguments; never execute package scripts or interpolate untrusted input into a shell.
- Forbid unsafe Rust unless an ADR, targeted tests and review explicitly justify an exception. Avoid panics on external input.
- Add acceptance tests before behavior changes, including negative security cases. Do not label extracted or downloaded content installable without the compatibility gate.
- Preserve the lockfile and use `--locked` for repeatable application builds. Keep public CLI behavior, diagnostics and generated documentation consistent.
- Record unsupported behavior and verification gaps honestly in `docs/progress.md`. For security reports use the private reporting process in `SECURITY.md`, not a public issue.
