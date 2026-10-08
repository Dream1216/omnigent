# Debian 13 glibc source experiment

This is a non-production source/backport experiment. Do not install its outputs
into a runtime until full glibc regressions, ABI/consumer verification and both
architecture full-image gates pass.

The source lock pins Debian's signed `2.41-12+deb13u4` DSC, both archives,
the developer keyring retrieved from the official Debian key service, and the
two upstream fixes. The DSC was verified against primary fingerprint
`77462642A9EF94FD0F77196DBA9C78061DDD8C9B`, signing subkey
`52BC8695BE34F90AD7D40CB81388C0F899E8336B`.

The repacked Debian orig archive must not be checked against GNU's signature
for different archive bytes. Its 20,048 shared source files match GNU 2.41
byte-for-byte; Debian omits 112 manual files. The Debian DSC authenticates
the actual repack. GNU's historical release signature verifies its own archive,
with a currently expired key recorded separately.

In an isolated Debian 13 builder, verify every locked material hash before
copying the pinned developer keyring into the builder's package-keyring path.
Extract with `dpkg-source --require-valid-signature --require-strong-checksums`.
Do not use `--no-check`, fuzzy patches or force application.

CVE-2026-5435's original patch fails on 2.41's final hunk context. The maintained
reviewed patch adapts only that context, preserves the old unknown-type
diagnostic and deletes the same 95 formatter lines as the upstream fix.
Their normalized deletion bytes have SHA-256
`67062ba4601e874dfc37e3e9e338c98f64fc5eacda9e7125e3ed0dd584dcbfdc`.
Both reviewed 5435 and original 19499 fixes passed `git apply --check` and
application to the extracted Debian baseline. The 19499 fix includes its
upstream next-to-fault-buffer regression test. These are not compiled results.

The curl replay helper's four-role detached-signature contract remains unchanged.
For glibc use the separate signed-DSC extraction contract, with every keyring and
reviewed patch hash verified. Build dependencies must be resolved from signed,
dated Debian indexes, not rolling packages or another distribution's libc.
