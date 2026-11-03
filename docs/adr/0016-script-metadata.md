# ADR 0016 — Maintainer script metadata

Status: Accepted for read-only metadata and private staging.

Inspection records the name, size and SHA256 of recognized control scripts (`preinst`, `postinst`, `prerm`, `postrm`, `config`) and reports whether a `triggers` file exists. Script and trigger content is untrusted: no shell or interpreter is invoked for it, it is not copied into the data staging tree, and its presence never grants execution permission. Trigger syntax and other control metadata are not yet analyzed. The execution admission policy remains deny-all until separate compatibility, action and transaction decisions are implemented.
