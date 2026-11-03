# ADR 0023 — Package integration indicators

Status: Accepted as non-authorizing `.deb` inspection evidence.

The bounded Debian archive reader records paths under `/etc`, systemd unit locations, pkg-config and CMake files, NSS configuration and locale trees. It also scans bounded file contents for a first-line shebang, simple absolute path tokens in UTF-8 text, and selected host-integration command names. Existing control metadata continues to report maintainer scripts and trigger presence; their bytes are never executed.

Findings are heuristic evidence only. Binary strings, generated paths, indirect commands, dynamic configuration, maintainer-script control flow, NSS/locale behavior and host assumptions may be missed; comments and documentation may create false positives. Archive member paths that are absolute or escape the root remain rejected. No result authorizes extraction into an active profile, execution, compatibility, or relocation. Scanning is bounded by existing archive, file and entry limits and by caps on reported findings.

Fixture acceptance covers representative path classes, embedded absolute paths, shebang and service-command evidence, plus existing hostile path and script tests. A complete compatibility report and an allowlist are separate roadmap milestones.
