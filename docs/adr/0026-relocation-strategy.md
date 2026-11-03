# ADR 0026 — Relocation strategy boundary

Status: Accepted for the current experimental compatibility subset.

| Option | Assessment |
|---|---|
| Preserve package paths and use an explicit stored-object path | Chosen only for the self-contained DSO class in ADR 0025. Bytes and package-relative path stay unchanged. This does not provide a profile or general prefix. |
| Patch RUNPATH | Not selected. It transforms signed artifact bytes, requires new object identities and audits for ELF layout, symbols, transitive dependencies, constructors and `dlopen`; current acceptance evidence does not support that risk. |
| Wrapper/custom loader | Not selected. Per-process loader arguments and search-path semantics vary by executable and do not solve service/configuration integration. |
| Mount namespace with original prefixes | Not selected. Requires a privileged or user-namespace boundary, collision policy, mount lifecycle and adversarial integration tests that are not implemented. |

Dich does not relocate or rewrite general Debian packages. The selected explicit-path behavior applies only to unchanged, self-contained shared objects and does not activate them. Other packages remain `review_required` or `unsupported`. Reopen this ADR only with a concrete runtime boundary and end-to-end tests; do not add transparent `LD_LIBRARY_PATH`, host mounts, or patching as convenience fallbacks.
