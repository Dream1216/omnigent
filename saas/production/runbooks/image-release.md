# Production image release runbook

Execution order and input selection live in `.github/release-pipeline.json` and
`saas-image-candidate.yml`; enforceable supply-chain requirements live in
`saas/supply_chain/release-policy.json`. This guide describes those contracts.
Conversation state and historical approval notes do not add execution gates.

The workflow records a plan for every PR and main push. Test/document-only changes
do not build OCI. Main pushes validate source through the existing CI rather than
starting a duplicate image build. Dispatch the candidate workflow for the final
protected product. A build-only dispatch retains the same sealed OCI needed by a
later signed dispatch. Pass its `candidate_run_id` to resume signing without a
rebuild; the resolver verifies the exact product, protected producer, successful
build, native artifact hashes and candidate seal before the existing full OCI
verification, current scans, signatures and independent registry readback.

Use the shared source checks with
`uv run python .github/scripts/ci/release_pipeline.py gate --stage source`.
File and line budgets produce visible size warnings under the current upstream
manifest. Lineage, version, forbidden paths, reverse dependencies, patch replay
and the isolation floor remain enforced. Recovery and final production checks
are available through `gate --stage recovery` and `gate --stage production`, with
their existing revision arguments and `--require-ready`.

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
job can publish the wheel plus Server and Host images and attach GitHub OIDC
attestations to those artifacts. Actual OCI vulnerability scans run before
promotion and after signed-image readback, with raw findings retained. Publication
does not perform the one-hour Canary, physical N-1 rollback or final production
evidence admission. Successful publication proves a signed candidate exists;
it does not authorize production deployment.

## Rollback

Retain the N-1 image digest, compatible database and adapter contract, patch
ledger, and rollback decision. Roll back application traffic only after schema
compatibility checks; never delete Runtime Partition, Identity Alias, Resource
Binding, revocation, Run Event, audit, usage, or migration evidence to make an
older binary start.
