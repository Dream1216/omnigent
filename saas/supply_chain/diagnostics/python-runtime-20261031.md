# Python runtime security diagnostic

The independent trust-registration candidate's Server preflight scan reported
one Critical and one High on each architecture: CVE-2026-115557 in Python
3.12.15-r3 and CVE-2026-114613 in py3-pip-wheel 26.2.1-r3. These are candidate
findings, not an observation of the currently deployed production image.

[Python 3.12.16](https://www.python.org/downloads/release/python-31216/)
contains the compromised eMudhra intermediate-key distrust fix. The
[Wolfi pip recipe](https://github.com/wolfi-dev/os/blob/main/py3-pip.yaml)
replaces the vendored msgpack source with 1.2.3 and certifi with 2026.10.23.
Both official APK indexes list Python/Python-base 3.12.16-r3 and pip-wheel
26.2.2-r2. Package availability and upstream release notes do not prove a
particular executable image is fixed.

The diagnostic workflow builds the shared `secured-python-runtime` stage in
two isolated architecture jobs. It changes exactly three pins in a temporary
Dockerfile and retains the original base digest, other direct pins, source
files and release lock. APK performs its normal signature verification.
The jobs check runtime versions and actual pip-wheel vendor contents, generate
SBOMs, and retain complete raw scans with zero Critical/High/ignored required.
Database age validation remains enabled. OCI archives, source/context hashes,
runtime facts and scanner metadata are available as seven-day artifacts.

The workflow has only repository read permission. It has no registry login,
image push, signing authority, cloud/model credentials, deployment or promotion
step. It uses the existing security gate and hash-pinned actions/scanners.

This is a diagnostic, not image or production admission. It does not modify
`wolfi-runtime-lock.json`, its existing admission field, trusted-input hashes,
the protected closure fixture or release thresholds. A passing result still
requires a separately reviewed runtime-source update, full application builds,
independent reproducibility, complete scans, signed release provenance and
the existing administrator/production gates. It does not resolve the separate
13 High findings in the vendor-compatible Aliyun Host image.

To inspect a run, choose `SaaS Python runtime diagnostic` in Actions. Check both
architecture jobs, download their artifacts and verify `SHA256SUMS`. Confirm
that `runtime-context.patch` contains only the three package pin changes,
`runtime-probe.json` shows Python 3.12.16 and the expected wheel contents, and
the raw reports agree with a zero/zero/zero summary. A missing probe or report,
a stale database, or a failed job must remain a failure.
