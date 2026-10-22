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
job can publish the wheel plus Server and Host images and attach GitHub OIDC
attestations to those artifacts. It still does not run vulnerability or license
admission scans, a one-hour Canary, an N-1 rollback exercise, or write the final
canonical production evidence object. Successful publication therefore proves
a signed candidate exists; it does not authorize production deployment.

## Rollback

Retain the N-1 image digest, compatible database and adapter contract, patch
ledger, and rollback decision. Roll back application traffic only after schema
compatibility checks; never delete Runtime Partition, Identity Alias, Resource
Binding, revocation, Run Event, audit, usage, or migration evidence to make an
older binary start.
