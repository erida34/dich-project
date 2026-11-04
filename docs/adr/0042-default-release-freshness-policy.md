# ADR 0042 — Conservative default Release freshness

Status: Accepted.

## Context

Requiring an explicit age flag made the documented `dich update` unusable without CLI policy knowledge. Some official Ubuntu Release files omit `Valid-Until`, so requiring that field by default also rejects the supported Ubuntu archive.

## Decision

CLI operations use a 24-hour maximum age by default. A signed `Valid-Until` is enforced whenever present. If it is absent, the signed `Date` must still be within the 24-hour maximum-age window. `--max-age-seconds` overrides the window; `--require-valid-until` rejects Release files without the field. The legacy `--allow-missing-valid-until` flag remains accepted for existing scripts; the two flags are mutually exclusive.

## Consequences

- `dich update` works without freshness flags on a current supported official archive.
- Missing `Valid-Until` has a bounded 24-hour freeze window, rather than no freshness check.
- A trusted local clock remains required; a compromised clock or signer remains outside the guarantee.
- Stale mirrors are still rejected. This policy does not lower the signature or digest verification requirements.
