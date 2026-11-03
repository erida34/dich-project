# ADR 0013 — Package action admission

Status: Accepted for package-code execution; profile selection has the narrow authenticated DSO path in ADR 0029.

Package metadata plans do not authorize package-code execution. An execution admission boundary must reject unexamined or incomplete evidence, dpkg database or host package-manager changes, maintainer scripts, services, kernel modules, triggers and global host state. Unknown action kinds fail closed rather than being interpreted as safe. The narrow ADR 0029 install path separately binds authenticated DSO closure evidence to verified content and selects metadata without loading code. This decision still denies launching arbitrary package commands or invoking their maintainer scripts.

The core admission gate continues to reject arbitrary package execution and host actions even when supplied empty evidence. The ADR 0029 DSO profile selection does not call this execution gate because it never loads or launches the package code; it uses authenticated repository and closure checks instead. This is not a sandbox or approval for arbitrary package contents.
