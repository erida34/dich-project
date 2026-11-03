# ADR 0026 — Relocation strategy boundary

Status: Accepted for the current experimental compatibility subset.

| Option | Assessment |
|---|---|
| Preserve package paths and use explicit stored-object paths | Chosen for the standalone DSO class in ADR 0025 and the narrow dependency closure in ADR 0027. Bytes and package-relative paths stay unchanged. This does not provide a profile or general prefix. |
| Patch RUNPATH | Not selected. It transforms signed artifact bytes, requires new object identities and audits for ELF layout, symbols, transitive dependencies, constructors and `dlopen`; current acceptance evidence does not support that risk. |
| Wrapper/custom loader | Not selected. The dependency closure uses the caller's glibc `dlmopen` API in an isolated link-map namespace; Dich does not provide a custom loader or wrapper. This remains specific to the tested DSO class. |
| Mount namespace with original prefixes | Not selected. Requires a privileged or user-namespace boundary, collision policy, mount lifecycle and adversarial integration tests that are not implemented. |

Dich does not relocate or rewrite general Debian packages. Explicit-path behavior applies only to unchanged DSOs accepted under ADRs 0025 and 0027 and does not activate them. Other packages remain `review_required` or `unsupported`. Do not add transparent `LD_LIBRARY_PATH`, host mounts, or patching as convenience fallbacks.
