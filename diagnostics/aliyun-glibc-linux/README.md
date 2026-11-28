# Debian glibc component qualification

This isolated diagnostic uses the exact Gen2 candidate Debian base and signed
glibc 2.43-7 source. It is not an application change or a production release.
The upstream v7 proposal is not asserted to be accepted or officially released.

Two independent jobs retain the default Debian build dependencies and build
profiles, native/i386/x32 package flavours, original tests and all raw results.
The control adds only the complete upstream regression test and its Makefile
entry. The candidate adds the original four-file context backport. The control
must fail only the added CVE regression; the candidate must complete packaging
with that regression passing and no unexpected failures. Expected failures and
unsupported cases remain visible. Neither `nocheck` nor `nobiarch` is used.

Native AMD64 exported symbols are compared to the actual distribution library.
Bash, Python, NSS/getent and iconv are executed with the freshly built dynamic
loader and library. These component consumers do not replace the complete Host
tool/runner checks or physical sandbox acceptance.

Inputs are authenticated using the original frozen public keyring, DSC, archive
sizes/checksums and the unchanged snapshot InRelease digest. The exact keyring
is public verification material. No cloud key, model credential, SSH agent or
production environment is passed to the build. Compilation has no network.
Packages keep upstream version 2.43 and carry an explicit local diagnostic
revision. They are not published or installed in production.

The canonical patch is stored as a readable JSON line array so repository
whitespace hooks preserve its exact upstream context bytes. Both the complete
candidate and derived test-only control are checked against their frozen SHA256
before they are written and strictly applied.

The result cannot reduce the existing Gen2 raw 13 High count. Whole-image raw
zero Critical/High, all Host contracts, image signatures, template readiness and
P1–P5 cloud/production acceptance remain required.

Local checks can validate pins and strict patch application. The Linux build
itself runs in the isolated CI jobs; inspect each raw `result.json`,
`*.tests.sum`, test details, package build log, exported-symbol lists and consumer
logs before interpreting its result. A green control job means its precisely
expected vulnerability was reproduced, not that the control is safe.
