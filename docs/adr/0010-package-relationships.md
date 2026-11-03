# ADR 0010 — Package relationship and host-base model

Status: Accepted for metadata modeling; solver integration remains pending.

Parse binary package relationship fields separately, preserving Depends and Pre-Depends groups and alternatives, version comparisons and multiarch qualifiers. Keep Conflicts, Breaks and Provides distinct; disallow alternatives in these fields and accept only exact versioned Provides. Preserve Multi-Arch as no, same, foreign or allowed rather than interpreting qualifiers prematurely. Mark Essential separately from Priority: required; neither is automatically provided by the host. Until a future, explicitly reviewed host-base policy exists, the resolver must not silently treat host state as satisfying a dependency or manage essential/required packages. This model is metadata, not a solver or ABI proof. Unsupported relation syntax must fail closed.

Tests exercise malformed relationships, alternative groups, versioned provides, multiarch qualifiers and independent essential/required flags. The model does not interpret architecture restrictions, build profiles or multiarch qualifiers, nor decide package satisfiability; the resolver must explicitly implement or reject these cases. Other relationship fields and maintainer actions are not modeled here.
