# ADR 0035 — Performance Budgets, Cold/Warm Metadata Sync, Deduplication, and GC Benchmarks

Status: Accepted for Phase 6 hardening and operational quality.

## Context

Dich manages versioned packages and execution profiles from Debian and Ubuntu repositories. As repository sizes, profile generation counts, and package trees scale, performance characteristics must remain bounded and predictable to ensure operational usability in CI/CD, local developer workflows, and automated deployments.

The project roadmap requires:
> Benchmarks for cold/warm metadata sync, package dedup and GC; performance budgets.

## Decision

### 1. Established Performance Budgets

To prevent algorithmic regressions (e.g. unintentional $O(N^2)$ scans, unindexed database queries, or redundant disk writes), Dich establishes strict maximum latency and throughput budgets for core operations on standard hardware (x86-64 modern CPU):

| Operation | Workload Description | Performance Budget | Target Expected |
|---|---|---|---|
| **Cold Metadata Parsing** | Parsing uncompressed 5,000-package `Packages` index and indexing candidates | $\le 500\text{ ms}$ | $\approx 6\text{–}60\text{ ms}$ |
| **Warm Metadata Revalidation** | Checking cached `InRelease` signature, validating `SnapshotJournal` floor, loading index | $\le 40\text{ ms}$ ($\le 100\text{ ms}$ debug) | $\approx 20\text{–}35\text{ ms}$ |
| **Package Deduplication** | Content-addressed SHA256 query and reuse check for already-committed tree | $\le 5\text{ ms}$ / pkg | $\approx 0.001\text{–}0.5\text{ ms}$ |
| **Garbage Collection (Scan)** | Root enumeration across active profiles and 1,000-object reachability traversal | $\le 50\text{ ms}$ | $\approx 1\text{–}15\text{ ms}$ |
| **Garbage Collection (Sweep)** | Dry-run sweep identifying unreachable trees and graphs | $\le 20\text{ ms}$ | $\approx 0.1\text{–}5\text{ ms}$ |

### 2. Benchmark Architecture and Tooling

Following the Ponytail principle of minimizing unnecessary dependencies and avoiding heavy frameworks, benchmarks are implemented using Rust standard library timing primitives (`std::time::Instant`) within a dedicated `[[bench]]` harness in `crates/dich-cli/benches/benchmarks.rs`.

The benchmark suite provides:
- **Reproducible fixtures**: Generates deterministic synthetic Debian package index stanzas (with realistic dependency graphs and version strings) and store object graphs without network access.
- **Warmup and Iterations**: Runs warmup iterations to stabilize OS page caches followed by measured iteration batches.
- **Statistical Output**: Reports min, mean, and max execution times, as well as throughput (items/sec or operations/sec).
- **Enforced Regression Checks**: In addition to the benchmark executable (`cargo bench`), an integration test in `crates/dich-cli/tests/performance_budgets.rs` asserts that all measured operations strictly adhere to their assigned budgets under normal test execution.

### 3. Invariants and Architectural Guarantees

1. **Cold Sync Invariant**: Index parsing uses bounded streaming readers (`tar`, `control_stanzas`), avoiding unbounded in-memory string copies and maintaining $O(N)$ candidate ingestion.
2. **Warm Sync Invariant**: When cached Release metadata matches the recorded floor identity and remains within Valid-Until/MaxAge, Dich avoids network round trips and re-parses indices only on demand.
3. **Deduplication Invariant**: Store identity is content-derived ($H(\text{artifact}, \text{policy}, \text{context})$). If an object identity already exists in SQLite `store_objects`, publication is an idempotent $O(1)$ database query and immediately returns `StoreOutcome::Reused`, skipping filesystem extraction and copy.
4. **GC Reachability Invariant**: Root discovery traverses only active profile `current` pointers and their ancestor rollback chains (`previous_id`). Reachability uses a visited hash set over graph edges, guaranteeing $O(V + E)$ traversal complexity without graph cycle hazards.

## Consequences

- Continuous integration verifies that operational commands remain snappy and within defined resource budgets.
- Regression testing immediately catches quadratic algorithmic slips before merging.
