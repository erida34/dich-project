# ADR 0022 — Bounded ELF evidence inventory

Status: Accepted for byte-level structural inspection in the `dich-elf` library.

Use the pinned `goblin` ELF parser instead of introducing a custom ELF parser or invoking a host `readelf` binary. The API accepts one byte slice, caps input at 128 MiB, bounds copied metadata and dynamic-symbol scanning, and reports malformed ELF as an error. It does not execute the object. Parser panics are contained at the API boundary.

The report records class, endianness, object type, machine number, interpreter, SONAME, DT_NEEDED libraries, RPATH/RUNPATH, GNU symbol-version requirements, and direct undefined imports of `dlopen`, `dlmopen`, `dlsym`, or `dlvsym`. Such imports are only a risk signal: static calls, function pointers, language runtimes, computed names and other loader behavior can be missed. A symbol version such as `GLIBC_*` is evidence, not a complete libc/ABI compatibility decision.

Acceptance uses fixed Ubuntu ELF fixtures plus malformed, non-ELF and over-limit inputs. This API does not yet traverse or inspect a `.deb`, produce an installability decision, compare a package dependency set, or support relocation. Compatibility remains unsupported until later Phase 4 evidence and policy milestones pass.
