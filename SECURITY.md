# Vulnerability reporting

Do not file an issue with exploit details or secrets. Use GitHub's **Report a vulnerability** flow only if private vulnerability reporting is enabled for this repository. No separate maintainer security contact is currently configured; before inviting external beta testers, enable private vulnerability reporting or publish a monitored private contact in the repository's Security settings.

Dich is experimental. It supports only authenticated x86-64 glibc DSO profile selection under the documented compatibility gate. It is not a general Debian package installer, does not execute maintainer scripts, and does not modify the host APT/dpkg database or system directories. Profile selection and `dlmopen` symbol-namespace isolation are not a process sandbox.
