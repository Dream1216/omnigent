# Preview Owner production authority

The Preview Owner uses its own NOSUPERUSER/NOBYPASSRLS login. It must not inherit
Gateway, platform, migration-owner or bootstrap authority. This installer adds
only the source-pinned Preview projection on an already verified P0S18 database;
it does not advance either Alembic head or change application rows. PG16 and
PG18 and the platform-admin/model-projection role profiles have separate exact
catalog anchors. The two existing gateway lease functions must retain native
SaaS-owner ownership. A retained legacy bootstrap-owned pair is still recognized
by existing verification, but this new projection has not qualified that owner
variant: installation rejects it before mutation instead of changing ownership.
Unknown heads, graphs and catalog drift fail closed.

## Release and rollback boundary

Deploy this repair as a new qualified product: the wheel contains a new SQL
resource and the Owner runtime binds transaction-local identity and token scope.
An existing frozen image does not contain this runtime repair. Bind the final
Main SHA, its own CI, signed wheel and images, migration receipt, accepted runtime
profile, role manifests and rendered service configuration to the same new
product. Keep existing data/PVC/project/Runner identities. Register a fresh Owner
instance and credential and issue its purpose-separated leaves; do not revive
an expired or released Owner. Advance the admitted runtime generation through
the existing signed promotion procedure and prove all consumers bind it.

Before writing, retain an independent database/volume backup and a verified
restore path, plus the old signed product/profile/manifests and receipt. A
physical rollback restores that consistent set. Reusing an old receipt after
this authority projection changes is rejected; rolling back only an image does
not restore the catalog. The release's normal security and rollout gates apply.

The receipt binds the product SHA, database identity, schema heads, role graph
and catalog; it has no OCI digest field. If the release chain already provides
a qualified signed wheel/CLI for that exact final Main before matching images
are ready, the approved zero-replica QA window can run installation and receipt
verification while image construction, scans, signing and distribution proceed.
Use the approved isolated execution context and the existing sole writer. Bind
the completed image tuple to the same product and receipt before starting Pods.
A different source revision requires its own matching receipt. This sequence
does not grant qualification to an unsigned wheel or to the old frozen image.

## Four-authority execution

Run the installed migration CLI from the qualified new product. Supply the
existing protected four-authority URL files, exact role-manifest files/hashes,
TLS configuration and matching OMNIGENT_SAAS_SOURCE_SHA and
OMNIGENT_SAAS_PRODUCT_REVISION. Never pass DSNs or tokens on the command line.
Use distinct fresh protected output paths for each receipt.

First authenticate the original catalog without mutations:

```sh
python -m saas.scripts.run_postgresql_migration \
  --product-revision "$OMNIGENT_SAAS_SOURCE_SHA" \
  --verification-saas-head p0s000000018 --verify-only \
  --output /run/protected-receipts/preview-before.json
```

After backup/restore verification, install the projection under the existing
migration advisory lock:

```sh
python -m saas.scripts.run_postgresql_migration \
  --product-revision "$OMNIGENT_SAAS_SOURCE_SHA" \
  --verification-saas-head p0s000000018 --install-preview-authority \
  --output /run/protected-receipts/preview-installed.json
```

Independently verify the complete installed projection without mutations:

```sh
python -m saas.scripts.run_postgresql_migration \
  --product-revision "$OMNIGENT_SAAS_SOURCE_SHA" \
  --verification-saas-head p0s000000018 --install-preview-authority --verify-only \
  --output /run/protected-receipts/preview-verified.json
```

The two final receipts must agree on database identity, product, schema heads,
role bindings/graph and catalog digest. Repeating installation must preserve
that catalog digest. Publish the final protected receipt/hash to all consumers
through the existing configuration rollout; the original receipt must fail as
stale. Do not hand-edit the receipt or install the test fixture SQL.

## Native acceptance

As the exact service login, prove both active client/server leaves, self/peer
Directory resolution, the TLS listener, scoped tunnel registration/redeem/
heartbeat/disconnect, and gateway heartbeat/release. Reject wrong login/token,
cross-Gateway or wrong-purpose/revoked leaves, expired leases, raw table DML and
registration-token-hash reads. Widened RLS, modified scope-function bodies and
partial ACLs must fail catalog verification and must not be repaired silently.
Keep original native evidence, public fingerprints and receipts; retain secret
material only in the existing protected mounts.
