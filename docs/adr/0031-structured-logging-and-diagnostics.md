# ADR 0031 — Structured logging, credential redaction, and stable error diagnostics

Status: Accepted for Phase 6 hardening and operational quality.

## Context

Dich operates on signed APT repositories, local stores, and execution profiles. Operators and automation need:
1. Stable, categorized process exit codes to distinguish command-line usage errors, policy rejections, resolution failures, and integrity violations.
2. Machine-readable JSON error outputs that retain compatibility while adding actionable hints and explicit exit code metadata.
3. Structured logging with strict credential redaction so that proxy credentials, auth tokens, or embedded URL secrets are never leaked to logs or stderr.
4. Clean progress output for multi-stage operations (`update`, `install`, `gc`, `rollback`) that informs human operators without contaminating stdout machine output.

## Decision

### 1. Categorized Exit Codes
Exit codes are standardized across all subcommands:
- `0`: Success
- `1`: General runtime / operational failure (e.g. store locked, I/O error, database error)
- `2`: Usage / CLI argument syntax error (standard Clap code)
- `3`: Policy / compatibility rejection (`unsupported`, `compatibility_rejected`, `unsupported_platform`, `profile_conflict`)
- `4`: Resolution / not found failure (`unsatisfiable`, `profile_missing`, `rollback_unavailable`)
- `5`: Integrity / security validation failure (`integrity_rejected`, `verification_failed`, `signature_failed`, `checksum_mismatch`)

### 2. JSON Error Schema and Helpful Hints
`CliError` contains an optional `hint` field recommending remediation steps (e.g. command alternatives or configuration flags).
The JSON error schema on stderr includes:
```json
{
  "schema_version": 1,
  "status": "error",
  "error": {
    "code": "unsupported",
    "message": "package execution and store mutation are not supported",
    "exit_code": 3,
    "hint": "Inspect packages with 'dich inspect <deb>' to examine compatibility evidence.",
    "trace": []
  }
}
```
Human output renders:
```text
dich: error: <message>
hint: <hint>
```

### 3. Structured Logging with Credential Redaction
- Logging is directed exclusively to `stderr`, preserving `stdout` for clean JSON and command data.
- Redaction runs over all log messages and field values:
  - URLs with userinfo (`scheme://user:pass@host`) are redacted to `scheme://***:***@host`.
  - Sensitive authorization header tokens (`Bearer ...`, `token: ...`) are replaced with `[REDACTED]`.
  - Private key blocks (`BEGIN ... PRIVATE KEY`) are replaced with `[REDACTED PRIVATE KEY]`.
- Configurable via `--log-level [off|error|warn|info|debug]` and `DICH_LOG`.
- In `--json` mode, logs format as single-line JSON records on `stderr`.

### 4. Progress Reporting
Interactive progress indicators are emitted to `stderr` during multi-step operations (`update`, `install`, `gc`, `rollback`), ensuring stdout remains machine-parseable.
