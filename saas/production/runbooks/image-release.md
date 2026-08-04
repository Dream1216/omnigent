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
accepted only if its digest is unchanged.

## Verification and promotion

1. Verify source, workflow, builder, base material digests, lockfiles, SBOM,
   provenance, signature identity, vulnerability policy, and license policy.
2. Start the image by digest with a disposable PostgreSQL instance; verify the
   reported product/upstream/schema/adapter tuple and run health, CLI, migration,
   login, RLS, Context, and OSS compatibility smoke probes.
3. Rebuild the same source with the recorded materials and epoch. Compare the
   platform manifest and configuration digests; investigate any rootfs or
   package difference before promotion.
4. Promote the immutable digest to canary, observe SLO and isolation probes,
   then update the deployment manifest by digest. A tag may aid discovery but
   cannot authorize deployment.

## Rollback

Retain the N-1 image digest, compatible database and adapter contract, patch
ledger, and rollback decision. Roll back application traffic only after schema
compatibility checks; never delete Runtime Partition, Identity Alias, Resource
Binding, revocation, Run Event, audit, usage, or migration evidence to make an
older binary start.
