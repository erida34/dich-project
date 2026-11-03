# Open design decisions

- Exact store layout and identity hashing scheme, including package split decisions.
- Dependency solving strategy: embedded Debian-versioned semantics vs libapt-pkg helper (Rust FFI compatibility tradeoffs).
- Future hardening of the gpgv/prlimit trust boundary and handling of mixed known/unknown signatures (ADR 0003).
- Preservation of package-relative usr/ path vs normalized prefix, and effects on RPATH/symlinks.
- General ABI environments remain open; the first install subset is x86-64 glibc DSO closures only (ADR 0029). Policy for other loader/libc environments, NSS and service packages remains open.
- Transaction journal and recovery model; SQLite durability and filesystem synchronization.
- Privilege boundary; user stores vs managed system store.
- Release owner, supported Debian/Ubuntu suites, stable release repository and signing process.
