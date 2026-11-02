# ADR 0005 — Debian metadata semantics

Status: Accepted for the parser and version-ordering library slice.

Parse Packages control stanzas as bounded untrusted input. Preserve RFC822-style continuation content and reject duplicate fields or ambiguous malformed input. Dependency relations must retain alternatives, version operators, architecture qualifiers/restrictions and build profiles without claiming the resolver implements them. Unsupported syntax must fail closed rather than being silently dropped.

Debian versions are compared by epoch, upstream version and Debian revision according to Debian's ordering rules: numeric runs compare numerically without integer overflow; `~` sorts before the empty string; letters sort before other non-digits; absent revision compares as `0`. Reject malformed versions, and verify ordering against `dpkg --compare-versions` as a read-only test oracle on Debian in addition to fixed fixtures. Version comparison alone says nothing about ABI compatibility or installability.

The current library retains restriction and profile tokens but does not interpret them, resolve virtual packages, or evaluate any dependency relation. Control continuations are preserved as newline-separated text with the first indentation character removed; the Debian description `.` marker is not converted to a blank line. An opt-in test parsed versions and Depends/Pre-Depends in the first 5,000 records of the cached Debian trixie main index on `dich-root`; this is evidence for that corpus, not proof of complete Debian syntax support.
