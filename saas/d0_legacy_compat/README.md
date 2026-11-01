# D0-retaining legacy compatibility proposal

This recipe keeps the exact M3659 0.18 runtime and dependencies, adds the six
byte-identical official U migration definitions, and adds independently derived
D0/T catalog constants. Existing verifier functions/classes remain unchanged.
The baseline advertises only the supported official head D0. The eight allowed
paths, original/patched digests, original signed wheel and paired base images
are pinned in `manifest.json`; the preparer pins that manifest's exact bytes.

The normal M3659 source prototype uses 184 upstream files against its unchanged
178-file cap and **does not pass that budget**. This bounded overlay is a new
review proposal. It inherits no old approval and grants no production authority.
The 0.21 product's separate existing source budget remains unchanged.

Download the original wheel from protected run `41221717927`, artifact
`13056135283`, verify its native artifact digest and GitHub attestation, then
materialize from a clean committed recipe checkout:

```sh
gh attestation verify /absolute/path/omnigent-0.18.0.dev20261006-py3-none-any.whl --repo Dream1216/omnigent
python -m saas.scripts.prepare_d0_legacy_compat \
  --wheel /absolute/path/omnigent-0.18.0.dev20261006-py3-none-any.whl \
  --output /absolute/path/fresh-unsigned-output \
  --source-revision "$(git rev-parse HEAD)"
```

The tool preserves all other wheel content, binds the exact recipe commit and
epoch, and regenerates wheel RECORD hashes. Its output is unsigned material for
review, **not an image, rollout approval or rollback qualification**.

Use the distinct `omnigent.postgresql-preserving-d0-compatible-t/v1` recovery
operation. It keeps D0 while reversing SaaS P18 to T and reattaching the exact
receipt objects on reentry. The original T protocol still refuses D0 before
mutation. An independent unfiltered reader rejects new/continued/delegated task
semantics and nonterminal dispatch states before any recovery write.

Remaining release work: independent review of this bounded source/material
contract; two reproducible builds of both paired compatibility images; raw
zero-High/Critical scans, signing and independent registry readback; actual old
Server/Host startup and business execution against the same migrated database;
all mixed-version combinations; independently restored full encrypted data and
the existing 900-second physical recovery limit. The native SQL and Store
probes do not replace these requirements.

## Paired image pipeline

`.github/workflows/saas-d0-legacy-compat.yml` builds an unsigned review candidate
on a pull request. It verifies native attestations for the exact original wheel
and both base indexes before materialization, then builds each image twice for
amd64 and arm64 without cache. Only the fixed eight payloads, source identity and
installed RECORD may appear in the added layer. Every original compressed base
layer, runtime command, user, environment, dependency and UI asset is retained.

The exporter checks the actual installed base and refuses source/metadata drift,
symlinks and existing cached bytecode; it never rewrites the installed base.
Both four-platform raw scans must contain no High/Critical or ignored findings
and use a database no older than 24 hours. Normal protected-main dispatch and the
`production-image` environment are required to publish the verified original OCI
archives, without rebuilding, under `compat-d0-<source-revision>` tags. Separate
index provenance and per-platform complete SPDX signatures bind the fixed
materials and pair. A separate read-only runner verifies all six native
signatures, exact registry bytes and fresh raw scans. Repacked archive digests
are recorded separately from the immutable original export digests.

A successful pipeline qualifies candidate material only. Actual runtime/business
compatibility, full data restore, mixed versions and production admission remain
separate required evidence; no deployment or database write occurs here.

The M3659 image build context omits README.md, so its installed METADATA keeps
exactly the signed wheel headers and final newline, without the long README
body. The exporter accepts only those two fixed byte forms derived from the
verified original wheel; all dependency, version, extra and other headers must
remain byte-identical, and no alternate description is accepted. METADATA is
never included in the overlay. The original first image-build refusal remains
evidence; this packaging distinction does not permit a dependency change.

Only the new overlay's file/directory timestamps are normalized before COPY.
The exporter must not request global timestamp rewriting of existing layers:
exact compressed base layer digest/size/media-type/order, all other descriptor fields and rootfs diff-id prefixes remain mandatory.
Original repeat comparisons and signed base layer descriptors are retained
before any rejection to make drift diagnosable without weakening that check.

BuildKit may retain, omit or update only its `buildkit/rewritten-timestamp`
annotation when inheriting a signed base. The validator accepts only the signed
value, omission or this committed source epoch for that annotation. Every other
annotation and descriptor field, compressed blob identity, cardinality and
rootfs diff-id prefix remains exact. The initial refusals and original native
comparisons are retained; annotation handling never permits a base byte change.
