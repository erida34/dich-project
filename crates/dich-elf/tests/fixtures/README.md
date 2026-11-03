`ubuntu-true` is a byte-for-byte copy of the WSL Ubuntu `/bin/true` ELF used as a dynamic-linking fixture (SHA256 `8a63c98320173f79e263115e10cefc170155e47d1fd4b5a70e4429d2699cae28`).

`dlopen-probe` is built from `dlopen-probe.c` in the same WSL environment with `cc -O0 -fPIE -pie`; it imports `dlopen` (`GLIBC_2.34`). SHA256: `e8f584e8fa2cbde815d080da32a794b21243d65e421215248a4b28ed6a7ab7b4`.

`ubuntu-true` and `dlopen-probe` are parser fixtures, not supported package examples. The pure shared object is a synthetic fixture for the narrow structural policy; it is not an upstream signed package or an installation authorization.

`libdich-fixture.so` is compiled from `pure-library.c` with `cc -shared -fPIC -nostdlib -Wl,-soname,libdich-fixture.so`; it has no interpreter, NEEDED entries, undefined dynamic imports, symbol versions, or loader paths (SHA256 `7b57b630fa6627296e0cf85afb47aad8447bec4ca9b20d9e3e2301d4960ee340`). `dlopen-checker` is a small host-linked test harness built from `dlopen-checker.c`; it loads a relocated copy by explicit path and verifies the exported function returns 42 (SHA256 `2f667d6fc04a81abc0bf33c7ff1f1899a1beeb5dae65f1d39238d1eead8e64a1`).

`constructor-library.so` is built from `constructor-library.c` with the same flags and includes a dynamic initializer; it is a negative policy fixture (SHA256 `09282306b0ca5410969876c4c989d010053dd7246ba030c8fce603471de8796b`).

`path-library.so` is built from `path-library.c` with the same flags and embeds `/etc/dich-fixture.conf` in `.rodata`; it is a negative absolute-path policy fixture (SHA256 `2e660d89cd050033144369e163f9ff1646c47eebc13e4f7bb1e9a37e6df36af2`).

`shared-libcommon.so` and `shared-libplugin-v1.so` / `shared-libplugin-v2.so` are dependency-closure fixtures built with `-shared -fPIC -nostdlib`. Both plugin versions have the same SONAME and `DT_NEEDED libcommon.so`; the common DSO exports the only imported function. `dlmopen-checker` loads the common object by explicit path in a new glibc namespace, obtains that namespace with `dlinfo`, then loads one plugin version into that namespace. Each version is tested in a fresh namespace on Ubuntu and Debian WSL. The test proves this small x86-64 glibc loader case only; it is not an installer, package resolver, signature test, or general ABI guarantee.

`shared-libcommon-alt.so` exports the same function as `shared-libcommon.so` under a different SONAME and exists to test rejection of ambiguous symbol providers. Missing-provider and duplicate-SONAME closures are also rejected by fixture tests.
