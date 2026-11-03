# ADR 0013 — Package action admission

Status: Accepted for the current deny-all execution boundary; archive analysis remains future work.

Package metadata plans do not authorize package execution. An execution admission boundary must reject unexamined or incomplete evidence, dpkg database or host package-manager changes, maintainer scripts, services, kernel modules, triggers and global host state. Until the future archive and compatibility analyzers exist, even a report with no detected actions is insufficient to authorize execution. Unknown action kinds must fail closed rather than be interpreted as safe. `install`, `remove`, profile activation and other store mutations continue to return unsupported; this policy does not execute, scan or extract a package. Future analyzer integration must bind its evidence to verified content and introduce explicit tests before any approval path is enabled.

Current CLI mutation commands invoke the core admission gate with unexamined evidence, and are rejected. The gate can classify reported prohibited categories but no archive analyzer currently supplies trusted reports. Passing an empty or supposedly examined list still cannot authorize execution. This is a verified deny-all boundary, not detection of package contents.
