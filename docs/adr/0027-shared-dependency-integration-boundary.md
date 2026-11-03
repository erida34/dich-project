# ADR 0027 — Isolated DSO dependency closures

Status: Accepted for a narrowly bounded, non-installing x86-64 glibc class.

## Context

ADR 0025 accepts one self-contained DSO. The Phase 4 integration gate also requires two package versions sharing a dependency. Ambient loader paths, RUNPATH rewriting and arbitrary wrappers remain out of scope (ADR 0026). A runtime boundary is needed that can resolve the exact supplied closure without changing ELF bytes or the caller's global loader namespace.

## Decision

`dich inspect ROOT.deb --with DEP.deb ...` accepts at most 16 caller-supplied archives and evaluates their combined ELF closure. Every data file must be one regular DSO under `usr/lib`, with path basename matching its SONAME. Only x86-64, little-endian ET_DYN objects are accepted. The closure must have unique SONAMEs, only internal `DT_NEEDED` edges, an acyclic graph, no duplicate global exports, and exactly one reachable in-closure provider for every undefined dynamic symbol. Interpreters, symbol-version imports or definitions, `dlopen` family imports, RPATH/RUNPATH, constructors, IFUNC, executable stack, W+X segments, absolute-path literals, scripts, triggers and host-integration markers fail closed. Analysis bounds the closure to 256 ELF objects, 65,536 dynamic symbol records and 512 evidence entries.

The report returns a dependency-first SONAME order. The tested runtime recipe creates a fresh glibc link-map namespace with `dlmopen(LM_ID_NEWLM, dependency_path, RTLD_NOW | RTLD_LOCAL)`, obtains that namespace with `dlinfo`, then opens each remaining object into the same namespace by explicit path. Each package version gets its own fresh namespace, so two versions can use the same dependency bytes without sharing symbol scope. `dich inspect` still does not authenticate local `--with` inputs. ADR 0029 separately permits profile selection only after signed-source authentication, bounded Debian dependency planning and this whole-closure rule pass; Dich returns explicit paths but still does not load code or provide a sandbox.

## Evidence and limits

Fixture packages cover a common DSO and two versions of a plugin with the same SONAME and `DT_NEEDED libcommon.so`. A C harness loads each version in a fresh namespace and verifies its result. Ubuntu Noble WSL and Debian 13 WSL both passed both versions. Negative fixtures cover a missing dependency and duplicate SONAME. This is not a sandbox: any later call into the DSO executes with the caller's privileges and can issue syscalls. The configured publisher must remain trusted. Other architectures, musl, symbol-versioned objects, dependencies outside the supplied closure, package scripts, and general Debian packages remain `review_required` or `unsupported`.
