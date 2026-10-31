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
