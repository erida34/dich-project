# Vulnerability reporting

Do not file an issue with exploit details or secrets. GitHub private vulnerability reporting is enabled for this repository; use **Security → Advisories → Report a vulnerability** for private disclosure. No separate maintainer security email is configured.

Dich is experimental. It supports only authenticated x86-64 glibc DSO profile selection under the documented compatibility gate. It is not a general Debian package installer, does not execute maintainer scripts, and does not modify the host APT/dpkg database or system directories. Profile selection and `dlmopen` symbol-namespace isolation are not a process sandbox.
