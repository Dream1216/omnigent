# Debian 13 curl source experiment

This recipe is an isolated compatibility experiment, not a production base image
or deployment admission. Do not wire its GnuTLS build into the runtime in place
of the existing OpenSSL build without TLS, HTTP/3 and ABI parity evidence.

The source replay helper verifies the locked archive and patch hashes before
extraction. It applies each patch atomically and reports conflicts as failures.
`production_admission` remains false even when replay succeeds.

The 8.14.1 baseline replays Debian's 27 patches, but 16 of the 18 additional
upstream security patches conflict. The 8.22.0 source replays its five Debian
patches successfully. GitHub commit comparisons on 2026-10-08 verified that all
18 security-fix commits in the 8.22 lock are ancestors of release commit
`01346829096c61b372692f6dc43ffa778c6caccd`. The original release tarball's
detached signature was verified with pinned primary fingerprint
`27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2`. Neither check proves compiled-image
security or compatibility.

## Reproduce

Run the helper tests from the repository root:

```sh
.venv/bin/python -m pytest tests/saas/test_debian_source_backports.py -q
```

Prepare a temporary Docker context containing this Dockerfile,
`saas/scripts/replay_debian_source_backports.py`, the 8.22 source lock renamed
`source-lock.json`, and the four hash-verified lock artifacts under `source/`.
Verify the detached tarball signature separately against the pinned fingerprint;
the helper does not itself verify OpenPGP signatures.

Build the `compile` target with the pinned Debian 13 Python base digest and a
numeric `SOURCE_DATE_EPOCH`. The base's own dated Debian snapshot comments select
the build dependencies; unsigned indexes or rolling cross-distribution packages
are not substitutes. Use an isolated worker with bounded CPU and memory.

The build runs curl's non-flaky tests before installation. Record configure
features, test outcomes, ELF dependencies and exported symbols for comparison
with the deployed image. A passing experiment still requires both runtime TLS
variants, both target architectures, full-image scans, SBOM/provenance and fresh
signatures tied to the eventual merged product commit.
