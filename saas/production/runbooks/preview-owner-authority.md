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

## Runner source and pool transition

A fleet stage must match the selected pool's source, schema, protocol and
adapter contract as well as its active placement. Changing only a StageSpec
from the old product to the new SHA fails before mutation. Use the existing
`SchedulingControlPlane.create_pool` entry point in
`saas/control_plane/scheduling.py` to create a new logical pool for the final
qualified product, on the existing active placement and its actual D0 schema.
Copy the approved queue class, capacity/reservations, protocol and adapter
contract from the verified current pool. Record the returned pool UUID; retain
the old pool and historical records. No new physical placement is required.

Pool and Runner source pins identify the final fork product. In contrast, the
existing RuntimePartition `source_revision` identifies upstream
`ee728a02004749e7f6971beee6c66d990bfbd216` and runtime
`0.21.0.dev20261031`; retain those actual placement/partition compatibility
facts. Do not replace every field named `source_revision` with the fork SHA.

In the existing approved zero-replica window, the sole runtime writer performs
this sequence with the matching qualified CLI and protected credentials:

1. Read the current two Runner UUIDs, pool, placement, source, generations,
   active leases and promoted admission epoch. Fence/drain or stop their old
   incarnations through the existing lifecycle. Both must be drained/offline
   with zero leases before staging; reconcile any old queued dispatches through
   their existing lifecycle, retaining historical data.
2. Create the new source-pinned pool through `create_pool`, with enough capacity
   for both retained members. Recreate each required tenant's reviewed queue
   share through `SchedulingControlPlane.configure_tenant_share`, using the new
   pool UUID and the existing weight, max concurrency and burst limit.
3. Reconcile business routing, execution bindings and rendered configuration.
   `RunDispatchProjector._resolve_pool` selects the single active pool by
   placement, tenant queue share, queue class, Run product revision, D0 schema
   and adapter contract. New Runs must carry the final product revision and
   select the new pool. `ExecutionProfileRecord` has no pool column: retain its
   UUID/config hash when its security policy is unchanged; update any external
   execution-profile or manifest pool references that actually exist. Do not
   invent a profile field or rewrite old dispatch rows.
4. Render the canonical A/B StageSpecs with
   `render_runner_database_fleet_stage_specs`: keep both original Runner UUIDs,
   instance keys, placement/failure domain, PVCs and actual capabilities, but
   bind both to the new pool and product. Run the existing
   `python -m saas.scripts.stage_runner_database_fleet` owner entry point. It
   locks the fleet and atomically advances each existing generation, updates
   its pool/source, issues fresh tokens and revokes old capabilities. Ordinary
   registration does not replace this same-UUID transition. Seal its one-time
   output in the existing fresh protected 0400 file; do not edit generations,
   source, pool or connection tokens with SQL.
5. Use the returned generations for the new Runner LOGIN/DSN and identity
   Secrets. Converge the existing narrow roles, issue/activate source- and
   generation-bound purpose leaves, revoke old incarnations, and complete the
   existing artifact-recovery and repository/mirror receipts. Retain PVC data
   and repository identities where their contracts permit; verify the new
   generation's actual bindings rather than relabelling old receipts.
6. Render the fleet, environment snapshot/context, trust pins, attestations and
   manifests from those actual results. Use the next admission epoch after the
   actual promoted maximum, then perform existing signature verification,
   admission and `promote_runner_database_fleet_after_admission`. Read back
   both original UUIDs with their new pool/source/generation and the accepted
   epoch. Do not hand-edit the old g3/epoch2 document or revive old credentials.
7. Keep the five migration-receipt consumers and two signed-fleet consumers
   distinct. Server, Worker, primary Owner, Edge and provider Edge consume the
   matching migration receipt; Runner A/B consume their signed fleet admission
   and context. The provider Edge keeps a separate gateway identity and does
   not become a third Runner registration.
8. After all final image/receipt bindings are ready, register a fresh matching
   primary Owner and prove its real active lease and renewals. Start the retained
   A/B Agents through the existing rollout, then prove heartbeat, Preview and
   actual business execution with the new routing. The old signed product,
   pool/manifests and independent restore evidence remain available for the
   existing qualified rollback procedure; no epoch decrement or token reuse
   is introduced by this transition.

## Native acceptance

As the exact service login, prove both active client/server leaves, self/peer
Directory resolution, the TLS listener, scoped tunnel registration/redeem/
heartbeat/disconnect, and gateway heartbeat/release. Reject wrong login/token,
cross-Gateway or wrong-purpose/revoked leaves, expired leases, raw table DML and
registration-token-hash reads. Widened RLS, modified scope-function bodies and
partial ACLs must fail catalog verification and must not be repaired silently.
Keep original native evidence, public fingerprints and receipts; retain secret
material only in the existing protected mounts.
