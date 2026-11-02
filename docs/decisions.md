# Open design decisions

- Exact store layout and identity hashing scheme, including package split decisions.
- Dependency solving strategy: embedded Debian-versioned semantics vs libapt-pkg helper (Rust FFI compatibility tradeoffs).
- Signed metadata verification library and Debian key handling with isolated trust roots.
- Preservation of package-relative usr/ path vs normalized prefix, and effects on RPATH/symlinks.
- Which ABI environments are permitted; policy for glibc, loader, NSS and packages requiring services.
- Transaction journal and recovery model; SQLite durability and filesystem synchronization.
- Privilege boundary; user stores vs managed system store.
- Release owner, supported Debian/Ubuntu suites, stable release repository and signing process.
