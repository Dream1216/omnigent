# Production image release runbook

## Build contract

Build only from a clean, immutable product SHA whose pinned upstream ancestor,
patch replay, source-intrusion budget, full OSS/SaaS regression, migrations, and
wheel contents pass. Resolve every base image to a digest before building and
record the exact lockfile hashes and `SOURCE_DATE_EPOCH`. Floating tags are not
deployment inputs.

The build emits an OCI digest, source and upstream labels, schema and adapter
labels, SPDX and CycloneDX SBOMs, maximum-mode provenance, vulnerability and
license reports, and a keyless signature tied to the protected workflow. The
attestations and reports name the same digest; a copied or retagged image is
accepted only if its digest is unchanged. The license report must bind
`omnigent-saas-license-admission-v1`, contain no denied or unknown licenses, and
carry no inline exception. An exception belongs in an independently approved,
expiring legal policy revision, never in a release record.

The production trust root is exact, not prefix-based: repository
`Dream1216/omnigent`, main-ref workflow
`.github/workflows/saas-image-candidate.yml@refs/heads/main`, GitHub Actions OIDC
issuer, the configured full workflow identity and OIDC subject, builder
`https://github.com/actions/runner`, and protected environment
`production-image`. Verify the signature subject digest and transparency-log
bundle. A matching issuer with a different workflow, ref, subject, builder, or
environment is rejected.

## Verification and promotion

1. Verify source, workflow, builder, base material digests, lockfiles, SBOM,
   provenance, signature subject and transparency log, a scanner database no
   more than 24 hours old, zero Critical/High vulnerabilities, and zero
   denied/unknown licenses.
2. Start the image by digest with a disposable PostgreSQL instance; verify the
   reported product/upstream/schema/adapter tuple and run health, CLI, migration,
   login, RLS, Context, and OSS compatibility smoke probes.
3. Rebuild the same source with the recorded materials and epoch. Compare the
   platform manifest and configuration digests; investigate any rootfs or
   package difference before promotion.
4. Publish only to the allowlisted immutable registry and retain its
   immutability receipt. Promote the exact digest to `production-canary`, observe
   it for at least 3600 seconds, and require both SLO and security gates.
5. Exercise N-1 rollback from the candidate to a different, digest-pinned prior
   image whose signature and provenance were verified. Recovery must complete
   within 900 seconds. Only then may release-engineering, security, and
   site-reliability provide distinct, post-operation approvals.
6. Write the canonical release evidence object last. Keep it inside the
   repository evidence path as a regular non-symlink file and bind it to the
   exact product revision. A tag may aid discovery but cannot authorize
   deployment.

Run the verifier from the protected release revision:

```bash
uv run python -m saas.scripts.check_image_supply_chain \
  --product-revision "$(git rev-parse HEAD)" \
  --require-ready
```

The `build-candidate` job in `saas-image-candidate.yml` repeats local OCI builds
and compares executable manifest/config facts. Its protected `publish-signed`
job publishes the wheel, Server/Host images and the separate MIT-core LiteLLM
runtime, and attaches GitHub OIDC attestations. Both architectures receive raw
Critical/High admission scans and SBOMs. The job does not complete legal license
approval, a one-hour Canary, an N-1 rollback exercise, or the final canonical
production evidence object. Successful publication proves that signed candidates
exist; it does not authorize production deployment.

### LiteLLM runtime artifact

The locked runtime is a separate component, not a substitute for either Server
or Host. Its two OCI builds use the exact product SHA and commit epoch, the
pinned vendor base and verified APK materials. The `litellm` label profile binds
the product/upstream/schema/adapter tuple, vendor digest, crypto version and
OSS-only distribution. Publication starts from its sealed first OCI archive;
no release step rebuilds it. Wrong artifacts, stale scan databases, missing
architectures and ignored findings fail admission.

The main-only `publish_signed=true` run transfers the original archive by exact
artifact ID, ZIP digest and producing run. It rescans before promotion, checks
registry readback, starts both architecture variants, generates SBOMs and signs
the immutable digest. Signed bytes are read back and scanned again. The final
registry verifier checks the exact source/workflow signature and sealed OCI
contents. It does not replay provider requests or claim live protocol acceptance.

Retain `litellm-oci-promotion-manifest.json` from candidate evidence and the
`litellm/` directory in the signed-release facts. The signed candidate's
`runtime_components.litellm` binds that separate seal and digest. Application
image evidence continues to require all four Server/Host raw reports; the two
LiteLLM reports cannot satisfy it. The complete workflow must pass before using
any of these components in the isolated recovery or production rollout.

## Rollback

Retain the N-1 image digest, compatible database and adapter contract, patch
ledger, and rollback decision. Roll back application traffic only after schema
compatibility checks; never delete Runtime Partition, Identity Alias, Resource
Binding, revocation, Run Event, audit, usage, or migration evidence to make an
older binary start.
