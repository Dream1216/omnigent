# Exact unsigned OCI runtime validation

The candidate workflow normally retains public build/scan evidence. A manual
run with `publish_signed=false` does not retain its executable OCI archives
unless `retain_unsigned_oci=true` is explicitly selected. Use that option when
qualifying the real installed runtime, private identity processes or one-shot
maintenance commands before production promotion:

```sh
gh workflow run saas-image-candidate.yml --repo Dream1216/omnigent \
  --ref codex/REVIEWED_BRANCH \
  -f publish_signed=false -f retain_unsigned_oci=true
```

Record the native run ID and resolved full `head_sha`. After that exact run
succeeds, download only its `saas-oci-validation-FULL_SHA` artifact into a new
private directory outside Git. Match the archive and promotion-manifest hashes
against the native candidate evidence for the same SHA, and verify the OCI
index, platform manifest, config and generated installed metadata before use.
Do not substitute a tag, a wheel with shared development dependencies, a local
rebuild or another run's archive. Keep tokens and secrets out of command lines
and evidence. The existing immutable promotion tooling supplies archive and
manifest validation; its protected publication requirements still apply to
production promotion.

The retained bundle contains the exact compared Server/Host archives, their
promotion manifest and raw scan evidence. It is uploaded only after two builds
of each multi-architecture image compare, both architectures pass the complete
fresh-database vulnerability scan, and the bundle is sealed. The export inherits
normal successful-step semantics; failed or incomplete builds cannot export it.
Archives expire after three days. Internal PR validation retains the same
bundle automatically. Fork PRs do not export it through this path.

This option grants no signing or registry publication authority. Signed runs
use their separate protected-main artifact and production-image environment;
setting both flags does not enable the unsigned export. Build permissions stay
`contents: read`. The source guard and export contract tests run in preflight
before expensive candidate builds.

Run the exact retained platform image in an owned isolated environment with
production entrypoints, full closed configuration loaders, generated build
metadata, real service-role bindings and a sealed database receipt. Exercise
real verified TLS, distinct reader/worker/maintenance secret sets, admission
failures and actual database/identity behavior. Verify process cleanup and
preserve secret-free observations with the exact image and input hashes.

An unsigned export is engineering evidence. It does not satisfy production
image signatures, protected source publication, independent identity/business
approvals, production network isolation, backup acceptance or deployment gates.
Do not write production acceptance records or activate the staged identity
Deployments based on this bundle alone.
