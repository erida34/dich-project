# ADR 0033 — Network transport hardening, offline mode, limits, and resilience

Status: Accepted for Phase 6 hardening and operational quality.

## Context

Dich sources Debian and Ubuntu packages and metadata over HTTPS. Production environments, CI runners, and air-gapped workstations require:
1. **Resilience to transient network failures**: Flaky network connections, load balancer drops, and transient HTTP 5xx errors should be retried with exponential backoff and jitter up to a strict limit, without retrying permanent errors.
2. **Offline mode**: Workstations in air-gapped, isolated, or reproducible build environments must be able to operate entirely from local authenticated caches with `--offline`. Network calls must be strictly blocked and fail closed with descriptive errors.
3. **Bandwidth and disk resource limits**: Network transfers must support bandwidth pacing to avoid saturating uplinks, and disk space must be checked before initiating downloads to prevent disk exhaustion.
4. **Cancellation and cleanup**: Interrupted or aborted downloads must immediately remove partial files and release locks without leaving orphaned stages.
5. **Adversarial race and descriptor robustness**: The transport and cache layers must withstand low file descriptor limits (`NOFILE`) and concurrent symlink/directory replacement attacks without data corruption or privilege escapes.

## Decision

### 1. Bounded Retries with Exponential Backoff
- The HTTPS transport implements bounded retries (maximum 3 attempts) for transient I/O errors and server-side HTTP status codes (429 Too Many Requests, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout).
- Non-retryable conditions fail immediately:
  - Client errors (400, 401, 403, 404, 410).
  - TLS certificate validation failures.
  - Freshness expiry, signature verification failures, or checksum mismatches.
- Backoff delays are bounded (100ms, 200ms, 400ms) with jitter.

### 2. Explicit Offline Mode (`--offline`)
- A global `--offline` CLI flag forbids any network socket creation or HTTP request.
- `dich update` fails immediately with an `offline_mode` error.
- `dich fetch` and `dich install` check if the required verified artifacts are already cached locally:
  - If all artifacts are cached and verified against the local snapshot journal, the operation proceeds completely offline.
  - If any required artifact is missing from cache, the operation fails with `offline_mode` and a diagnostic hint to run `dich update` and `dich fetch` while online.
- Read-only metadata operations (`search`, `show`, `versions`, `plan`) operate from cache without contacting repositories.

### 3. Resource Limits (Bandwidth & Disk)
- Bandwidth throttling: Bounded read wrappers allow configuring an optional byte-per-second transfer rate limit.
- Disk capacity preflight: Before downloading artifacts, available disk space is verified against requested byte sizes to prevent partition exhaustion.

### 4. Cancellation & File Cleanup
- Streams and staging helpers clean up temporary staging files via RAII guard destructors on error or abort.
- `SnapshotJournal` lock files and temporary download files (`.tmp-*`) are unlinked when a stream or transaction terminates unexpectedly.

### 5. File Descriptor & Race Resilience
- Negative integration tests verify that running under restricted file descriptor limits (`prlimit --nofile=...`) fails closed safely without resource leakage or panics.
- Symlink races and concurrent filesystem mutations fail closed against descriptor-relative `O_NOFOLLOW` checks.

## Consequences

- Dich operates reliably in intermittent network conditions and strictly conforms to air-gapped offline requirements.
- Memory, disk, and socket resources remain bounded even under adversarial stress.
