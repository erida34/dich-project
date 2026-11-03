`ubuntu-true` is a byte-for-byte copy of the WSL Ubuntu `/bin/true` ELF used as a dynamic-linking fixture (SHA256 `8a63c98320173f79e263115e10cefc170155e47d1fd4b5a70e4429d2699cae28`).

`dlopen-probe` is built from `dlopen-probe.c` in the same WSL environment with `cc -O0 -fPIE -pie`; it imports `dlopen` (`GLIBC_2.34`). SHA256: `e8f584e8fa2cbde815d080da32a794b21243d65e421215248a4b28ed6a7ab7b4`.

These files are parser fixtures, not supported package examples or compatibility allowlist entries.
