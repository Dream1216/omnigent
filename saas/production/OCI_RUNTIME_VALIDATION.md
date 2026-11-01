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

For a first-attempt manual run, use the separate unsigned transfer tool. Obtain
the artifact ID, ZIP digest/size and exact run facts from GitHub's native API;
capture the promotion-manifest SHA-256 independently from that run's small
candidate-evidence artifact. Choose explicit download, expanded-byte and free
space reserve budgets before requesting any executable bytes:

```sh
python -m saas.scripts.download_oci_validation inspect \
  --repository Dream1216/omnigent --revision FULL_SHA \
  --run-id RUN_ID --artifact-id ARTIFACT_ID \
  --output-dir /private/new-validation-bundle \
  --max-download-bytes DOWNLOAD_BUDGET \
  --max-expanded-bytes EXPANSION_BUDGET --reserve-bytes FREE_SPACE_RESERVE
```

`inspect` fetches only native metadata and writes no files. A failed, unfinished,
forked, different-workflow or repeated-attempt run is rejected. The ZIP must be
named `saas-oci-validation-FULL_SHA`, with a native digest and exact run/source
binding. After capacity coordination permits transfer, repeat the command with
`download` and `--manifest-sha256 INDEPENDENT_MANIFEST_SHA256`. The output must
be new, with an existing resolved parent. Transfer is bounded by the native ZIP
size, digest and timeout; extraction also checks the total declared expanded
bytes, manifest digest and current free space. The temporary ZIP is removed
after extraction, following the existing promotion download behavior.

The capacity report covers simultaneous ZIP and extracted bundle storage. It
does not reserve filesystem space against concurrent writers or include OCI
inspection scratch space, platform extraction or container storage; budget
those separately. A capacity report does not override an outstanding transfer
hold. The transfer receipt explicitly leaves candidate-seal verification and
runtime qualification false. Next verify the full sealed candidate with
`oci_promotion.verify_candidate`, using the independently captured manifest
digest, exact source epoch and labels, and fresh scans as required. The existing
`oci_promotion download` remains restricted to protected promotion artifacts;
the unsigned helper grants no signing or publication authority. Internal PR and
rerun artifacts require their own reviewed native attempt binding and are not
accepted by this manual transfer helper.

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

Candidate preflight also builds a backend wheel and checks its actual members,
including the Casdoor source lock, referenced patch, build recipe and maintenance
runbooks. The full reader/worker and credential-import configuration loaders
read that installed source lock; a source checkout or fixture-composed service
can hide a missing wheel resource. A passing member check still requires the
real image's closed configuration, entrypoints and installed metadata tests.

`MANIFEST.in` includes the source kit in source distributions and wheels through
the existing `include-package-data` setting. The Server builder stages that
manifest alongside its packaging inputs. This preserves the exact trusted
`pyproject.toml` bytes required by the N-1 workflow policy. Candidate preflight
also checks all 21 trusted N-1 inputs before starting the complete regressions;
do not replace those policy digests to accommodate unrelated packaging changes.
