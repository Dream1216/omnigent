# Beta/Production SaaS runtime deployment

This directory contains fail-closed deployment templates for the downstream
server, the Run Outbox/scheduler worker, and the one-shot four-authority
PostgreSQL migration. The K3s path is authoritative for `next.jxhh.com`.

## Admission status

The rendered profile becomes **Beta-deployable only after** its external PG18,
Runner database-fleet, repository-mirror, artifact, PKI, containment, and
stability admission receipts all pass for the same release. Until then it is a
fail-closed candidate with `p0s000000011` and exactly
`tenant,run,runner,preview`. The source Runner A/B Deployments deliberately have
`replicas: 0`; stage rendering keeps every long-running Deployment at zero, and
only the trusted final renderer may restore the reviewed Server/Worker/Edge/Owner
counts and Runner A/B to one after every required receipt is non-pending and
release-bound. The isolated landing zone is namespace
`omnigent-next-beta`, and its reviewed GitOps desired-state path is
`targets/next/beta/20260902/v1`. A trusted renderer must rewrite every manifest
namespace and namespace-qualified Service name together; applying this source
template directly to `omnigent` is forbidden.

The Beta database boundary is a dedicated CNPG PostgreSQL 18 cluster named
`omnigent-postgres` in namespace `omnigent-next-beta-data`, with the empty
synthetic-only database `omnigent_next_beta`. Its write Service is
`omnigent-postgres-rw.omnigent-next-beta-data.svc.cluster.local:5432`. The
trusted Beta renderer converges the six reviewed PostgreSQL NetworkPolicy peers
from the source production namespace `omnigent-data` to that dedicated data
namespace. These exact four application manifests do not create a CNPG
`Cluster`. A separately reviewed external GitOps application must own the Cluster,
its digest-pinned PostgreSQL 18 image, parameter desired state, restart, storage,
backup, and recovery configuration; it must be Synced/Healthy before migration.
After the required restart, secret-free admission evidence must show both
`max_notify_queue_pages=64` and `max_prepared_transactions=0` with
`context=postmaster`, `source=configuration file`, and
`pending_restart=false`, plus `SELECT count(*) FROM pg_prepared_xacts` returning
`0`. A missing row, a different value/source/context, a pending restart, or any
prepared transaction fails closed. PostgreSQL 16 is N-1 compatibility-only and
is not a deployable Beta database: `max_notify_queue_pages` being absent and a
direct Runner connection being expected-deny are compatibility evidence, not
Beta admission evidence. Never modify the live `omnigent-data` database ACLs to
make a Beta rollout pass.

This is **not Production-admitted**. Production remains blocked by the
process-local singleton Preview Owner, missing observed backup/PITR and restore
evidence for the release database, external Runner/Preview PKI issuance and
revocation/rotation evidence, exact artifact/repository IAM plus frozen endpoint
CIDRs, the policy-required two-replica egress proxy with verified
`runner_egress_proxy_only` enforcement, and reviewed NLB/HAProxy/DNS routing
governance with rollback proof. The single-repository Beta stager is also not
evidence for production multi-tenant repository fan-out. Beta acceptance does
not waive any of those gates.

No source manifest contains a usable image, Git revision, credential, or cluster
network identity. Concrete downstream adapter factories are fixed in the
template, while every all-zero digest/SHA and every `replace.*` value must be
replaced in a release copy before server-side apply. The image reference is always
`repository@sha256:<digest>`; tags and local builds are not admitted.

## Required order

1. **External PG18 desired state and identity bootstrap.** Reconcile the
   separately reviewed CNPG GitOps application, including the digest-pinned
   PostgreSQL 18 image, `max_notify_queue_pages=64`, and
   `max_prepared_transactions=0`, and complete the required restart before any
   database authority runs. Do not continue unless both `pg_settings` rows have
   `context=postmaster`, `source=configuration file`, and
   `pending_restart=false`, and `pg_prepared_xacts` is empty. Then provision
   every long-lived service login that this release will deploy. At a minimum
   this means the exact thirteen-entry service-role manifest. Its fixed
   service-to-base-role profile is `runtime -> omnigent_runtime_app`,
   `authenticator -> saas_authenticator`, `app -> saas_app`,
   `governance -> saas_governance`, `public_api -> saas_public_api`,
   `dispatcher -> saas_dispatcher`, `executor -> saas_executor`,
   `onboarding -> saas_onboarding`,
   `onboarding_status -> saas_onboarding_status`,
   `secret_broker -> saas_secret_broker`, `preview_edge -> saas_preview_edge`,
   `preview_owner -> saas_preview_owner`, and
   `registration -> saas_registration`; the thirteen unique login names are
   release inputs. Each login must inherit exactly its one corresponding
   NOLOGIN base role with no creator/admin option edge, direct object grant,
   ownership, `SET ROLE` option, role setting, or bypass flag.
   This bootstrap is deliberately outside the migration Job. The Job converges
   capability roles and schemas but never creates a service login.
2. **Four-authority migration through P0S10 and roles.** Provide four distinct
   Kubernetes Secrets—principal operator, database owner, official schema owner,
   and SaaS schema owner—and run `kubernetes.migration.yaml`. Each Secret contains only a
   `value` key holding one TLS `postgresql+psycopg` URL. The init container copies
   each mount to a separate owner-only file; no DSN is placed in an environment
   variable or command line. The same canonical, owner-only
   `service-role-bindings.json` is mounted into this Job, the server, and the
   worker.
   The driver order is fixed and fail-closed: `postgresql_principals.sql` then
   `postgresql_database.sql`, official Alembic, SaaS Alembic through exact head
   `p0s000000011`, the runtime and control-plane projections from
   `postgresql_roles.sql`, and the final database ACL projection and verifier.
   A different or partial order is not an admissible receipt.
   Before this phase, the cluster owner or audited superuser must revoke
   `CONNECT`, `CREATE`, and `TEMPORARY` from `PUBLIC` on every database in the
   cluster. Explicitly grant the reviewed principals on the target database;
   no Runner LOGIN or `saas_runner_agent` may effectively connect to any other
   database. The migration Job intentionally cannot converge databases owned by
   another authority. Each Runner rechecks the effective cluster-wide database
   projection before every claim and remains unclaimable until it is exact. For
   Beta this convergence occurs only in `omnigent-next-beta-data`; the shared
   live cluster is not a fallback target.
3. **Managed-superuser Runner cluster admission.** After the migration Job has
   reached its roles and final verifier, but before any evidence is frozen, use a
   short-lived, audited managed-cluster superuser channel to execute the packaged
   `saas/control_plane/postgresql_runner_agent_cluster.psql` wrapper against the
   exact Beta database. The wrapper uses `ON_ERROR_STOP` and one transaction to
   run `postgresql_runner_agent_cluster.sql`, validate PostgreSQL 18 and the two
   effective postmaster settings, reject any `pg_prepared_xacts` row, revoke the
   unsafe built-in routine surface, grant only the reviewed central-service
   support signatures, and assert the final Runner denial boundary. The
   superuser DSN or credential must never enter the four-authority migration Job,
   the application namespace, a long-lived Pod, an environment variable, a
   command line, a receipt, or transcript-visible output. The audited external
   channel must retain secret-free evidence containing the wrapper and SQL
   SHA256, Cluster UID, image digest, server major, the exact `pg_settings` rows,
   zero prepared transactions, final routine-denial assertions, operator
   identity, and execution time.
4. **Freeze the coupled evidence.** Treat the Job's success log as a candidate
   receipt until the managed-superuser admission and its secret-free evidence
   have also passed. Both Alembic environments suppress informational output in
   non-debug runs, so a successful Job emits exactly one JSON document; any
   warning/error is a failed evidence run and must not be filtered into a
   receipt. Verify `status=pass`, `state:verified`, the exact
   `product_revision`, and the canonical service-role bindings SHA256, then
   provision it as the immutable `omnigent-saas-migration-receipt` Secret.
   Adding or changing one of those thirteen service logins or memberships after this
   point invalidates the manifest and security-catalog digests and requires a
   new verify-only receipt. The release evidence ledger must freeze the candidate
   receipt SHA256 and the managed-superuser evidence SHA256 together; the
   Kubernetes Secret contains only the existing migration receipt, never admin
   output or credentials.
5. **Provision narrow runtime files.** Create five distinct server DSN Secrets,
   separate dispatcher/executor/Preview-Edge/Preview-Owner DSN Secrets, five
   application-key files, and two per-incarnation Runner-agent DSN Secrets. Each
   Runner login is an external machine identity named exactly
   `runner_<runner_uuid_without_hyphens>_g<connection_generation>` and inherits
   only `saas_runner_agent`, with the exact PostgreSQL `CONNECTION LIMIT 8`
   required by its fixed `pool_size=4,max_overflow=4` engine budget. Unlimited
   `-1`, disabled `0`, or any other connection limit is fail-closed. That machine
   capability is deliberately outside the
   canonical exact-thirteen service-role binding manifest: adding any Runner
   machine identity to that manifest is invalid. The manifest references each DSN only through its own
   Kubernetes Secret and never embeds a login or URL. Also provision the
   Server artifact credential, a distinct immutable artifact credential
   for each Runner incarnation, the Runner-control server TLS Secret, two
   pre-registered Runner identity Secrets, the Preview relay client/server
   TLS Secrets,
   and the deployment-owned adapter factories. The server receives five service
   DSNs; each other process receives only its reviewed service authority. No
   long-running process receives an owner or migration authority.
   Every authority and runtime DSN must target `omnigent_next_beta` through
   `omnigent-postgres-rw.omnigent-next-beta-data.svc.cluster.local`; a DSN for
   `omnigent-data`, `postgres`, or another database is rejected release input.
6. **Stage and admit the exact Runner database fleet while every workload is
   stopped.** The owner-only stage command
   `omnigent-saas-runner-database-fleet-stage` takes one canonical schema-1 file
   containing exactly two entries sorted by Runner UUID, locks the registration
   table, and creates or fences A/B directly into `draining` with zero active
   leases. It never calls ordinary registration and therefore has no transient
   `online` window. The command writes the two distinct one-time connection
   tokens only to a newly reserved owner-only mode-0400 file in a mode-0700
   directory; stdout is secret-free. External provisioning derives the two
   canonical per-generation logins and DSN Secrets from that protected output.
   With all long-running Deployments still at zero, create a canonical evidence
   context and owner-signed environment attestation from independently observed
   Kubernetes/CNPG metadata. The attestation binds the exact CNPG Cluster UID,
   database OID/system identifier, write Service/Endpoints, A/B Deployment UID
   and pod-template hash, A/B DSN Secret UID/resourceVersion, registration
   ID/generation/status, product SHA, image digest, namespace, release
   incarnation, and fleet/context/catalog source hashes. Its issuer, key ID,
   public-key fingerprint, and digest are GitOps-pinned public inputs; neither
   signing key nor managed-admin DSN enters a workload Pod.
   Run `omnigent-saas-runner-database-fleet-admit` through the audited
   owner-only read-only database channel. It verifies the exact two-login
   namespace, memberships, flags, rolconfig, database identity/target, PUBLIC
   effective denial, complete base-role ACL/policy/ownership projection, and
   absence of a third active registration or stale login. It emits a canonical
   Ed25519-signed, secret-free admission receipt. Then run
   `omnigent-saas-runner-database-fleet-promote`; inside the same table lock it
   obtains database `clock_timestamp()`, re-verifies canonical signature,
   audience, release, five-minute promotion deadline, monotonic epoch, complete
   registration projection digest, exact A/B `draining`/zero-lease state, and
   atomically changes both rows to `online` with their outbox events. Any partial
   or concurrent third registration rolls back the whole promotion. The
   five-minute expiry is a promotion deadline only: after a successful promotion
   the runtime continues from the immutable Pod-pinned receipt and live catalog,
   rather than self-destructing when that deadline passes. Startup and every
   claim revalidate the signed fleet/catalog/registration projection; drift is a
   sticky poison.
7. **Pre-provision the exact-one repository profile.** This isolated Beta
   manifest supports exactly one reviewed binding named `primary`. Each
   canonical provisioning spec must declare
   `expected_binding_keys=["primary"]` and bind its sole credential file to
   `/provisioning-private/credentials/primary.credential`. Before stage and
   final rendering, a sealed owner rehearsal must produce nonzero spec,
   bindings, and receipt SHA256 values for each Runner slot; init output is never
   accepted as its own trust root. The per-slot immutable provisioning-spec
   Secret name is derived from release incarnation, slot, and spec SHA; the
   credential Secret name is derived from a non-secret credential revision.
   Only init mounts those two Secrets. Init installs exact mode-0400 inputs,
   reproduces the three pinned hashes, and writes mirrors, canonical bindings,
   and receipt under the separate `/repository` volume. The trusted Runner main
   process mounts `/repository` read-write because Git worktree add/remove must
   update bare-mirror metadata; `/work` is a different volume, and the untrusted
   official sandbox's cwd/read/write grants must never include `/repository`.
   Production multi-binding or multi-tenant repository fan-out remains blocked
   until an owner-rendered exact `items` and copy projection, or an independently
   admitted safe stager, handles every expected key without wildcard copies.
8. **Prove artifact CRUD for this release incarnation.** Generate a fresh
   128-bit lowercase-hex release incarnation, render it into both manifests and
   every `replace-release12` resource name, run the revision-scoped artifact
   admission Job, and freeze its exact content hash in the Server release facts.
   The Server rejects a receipt from another source SHA, image, release
   incarnation, endpoint, region, store URI, credential file, or incomplete key
   space. Never reuse a previous incarnation to make a new rollout pass.
9. **Apply beside live traffic.** Apply `kubernetes.network-policy.yaml` and
   `kubernetes.production.yaml` in the isolated namespace and verify their
   ClusterIP services before switching traffic. This
   application template intentionally contains no Ingress, cert-manager, Traefik,
   `hostPort`, or `NodePort` resource.

The scheduler container closes `Outbox(run.queued) -> RunDispatch` plus bounded
expired-lease recovery. Its colocated Runner-control container exposes the
existing fair claim, Runner/Run heartbeat, fenced transition, terminal release,
and recovery semantics over a one-command TLS 1.3 mTLS protocol. Runner identity
comes only from the certificate URI SAN and must also match the current database
connection generation/token. Lease TTL, capability actions, scope, and requeue
policy are server-owned; the protocol has no automatic mutation retry.

The separate Runner-agent entrypoint consumes claims, transitions leased Runs
through `starting`/`running`, heartbeats the exact lease while the existing
managed Runner executor runs, then performs a one-shot terminal transition and
release. Its client certificate URI identity must equal the configured Runner ID,
while the server independently binds that identity to the current database
connection generation/token. The executor factory must adapt the existing managed
Host/Runner runtime; it is not permission to deserialize a command or build a
second execution kernel.

Each Runner agent uses a per-incarnation database authority that is distinct
from the shared `saas_executor` authority retained by the central worker and
Runner-control process. Runner A and B must receive different DSN Secrets and
canonical logins derived from their exact Runner UUID and connection generation;
neither Runner pod mounts the executor DSN, migration receipt, or canonical
service-role binding file. A replacement Runner identity requires a new login,
DSN Secret, connection token, certificate, and durable registration generation.
External provisioning must set each per-incarnation LOGIN to `CONNECTION LIMIT
8`; the Runner rejects `-1`, `0`, or any other observed value before claiming.

The p0s10 Runner authority is a Beta boundary, not Production admission. Its
exact RPC/ACL projection now closes the previously identified direct raw-DML
transition surface, and each Runner verifies that projection before startup and
every claim. Beta still uses direct database connectivity without an enforcing
egress proxy, and centralized orphan/GC, cross-host containment, operational
rotation, and live policy evidence are not closed. Deploy it only with synthetic
tenants, an empty or scrubbed database, non-production secret material, and no
production traffic. Isolation-grant or secret-lease forgery, capability-action
separation, FORCE-RLS, catalog/database drift, any third Runner login or
registration, and missing signed fleet receipts block even Beta. The absence of
an enforcing proxy and central GC remains an explicit Enterprise Production
NO-GO despite the p0s10 RPC/ACL closure.

The dedicated Beta cluster uses retained storage and contains no production
tenant data. Application or traffic rollback quarantines the Beta namespace,
revokes its login/certificate/token material, and leaves the CNPG Cluster and
`omnigent-local-retain` PVCs intact for evidence; rollback must not delete the
database or PVCs. Retained PVCs are not backup, PITR, or restore evidence.

One Runner Deployment is one immutable Runner incarnation and uses
`strategy: Recreate`; a rolling update with the same Runner ID and connection
generation is forbidden. The Beta manifest carries two such Deployments,
`omnigent-saas-runner-agent-a` and `omnigent-saas-runner-agent-b`, with distinct
identity, repository-binding, and recovery Secrets. Required component
anti-affinity places them on different `kubernetes.io/hostname` values. Each
recovery URI must end in the exact
`runner/{runner_id}/generation/{generation}` prefix and its immutable Secret name
must be unique to that incarnation. The credential file SHA256 is the configured
credential revision and pod-template annotation. External object-store IAM must
grant only HEAD/GET/PUT below that exact prefix, deny bucket listing,
cross-prefix access, overwrite, and delete, and enable versioning/Object Lock.
A shared fleet credential or a Secret/revision mismatch is a failed admission,
not a rollout warning.

The source A/B Deployments remain at `replicas: 0`. A trusted stage render also
sets Server, Worker, Preview Edge, Preview Owner, and both Runners to zero while
the migration and artifact Jobs run. Final rendering is the sole authority that
may remove `runner-fleet-admission-pending`, pin the signed admission receipt and
public-key fingerprints, set A/B to one, and restore the other reviewed replica
counts. Rotation reverses that order: render the affected workload to zero,
drain and prove zero leases, revoke/fence the old registration and login, create
a fresh generation/token/login/DSN/identity, repeat signed environment and
database admission, atomically promote, then render it online. A tombstoned or
fenced identity is never revived and no token, private signing key, or admin DSN
may be copied into the fleet public Secret.

That fleet Secret is an explicit public-only projection, not a wildcard mount.
Its exact nine keys are fleet, evidence context, trust pins, environment
attestation JSON/signature/public key, and admission receipt
JSON/signature/public key. `items` and mode 0400 are renderer-audited for both
A/B; an extra admin DSN, private signing key, missing key, or renamed path fails
before output is written. The source Secret volume is init-only, and the Runner
main container receives only the copied public files in its bounded runtime
volume.

The certificate-authorizer factory remains a required deployment trust input and
must enforce external PKI revocation for purpose `runner_control`. The template
will not start without the CA/server leaf/key Secret or the authorizer. This is
real machine-control code and a fail-closed deployment contract, but external
CA/HSM issuance, revocation, and cross-host execution remain unproved and
must not be used as production evidence. The template advertises exactly
`tenant,run,runner,preview`: the Server receives only public Runner-control and
Preview-readiness CAs and uses
the fixed TLS 1.3 readiness protocol on the internal Service. The readiness
response is content-blind and is returned only while Runner control can observe
one current compatible durable Runner; the Server receives neither an executor
DSN nor a Runner client/server private key.

The Preview Edge uses the concrete
`saas.production.preview_relay:build_production_preview_tunnel` composition and
only the `saas_preview_edge` login. Every directory-selected Relay endpoint is
restricted to the rendered internal DNS suffix, Pod CIDR, and TCP port; all DNS
answers must satisfy the CIDR policy and the connection is pinned to one checked
address while TLS retains the directory-selected server name. Loopback,
link-local/metadata, multicast, reserved, public, and unrelated private addresses
fail closed. The TLS 1.3 mTLS peer certificate and durable Placement owner are
then rechecked without request replay.

Server and Worker Preview readiness is a separate, content-blind TLS 1.3
`/readyz` endpoint. The adapter
`saas.production.preview_readiness:build_remote_tls_preview_readiness` accepts no
caller-selected URL and receives no Preview DSN or client credential. It pins
the rendered internal DNS name, server name, public CA, Service CIDR, and TCP
port, validates every DNS answer, connects to one checked numeric address, and
accepts only the exact bounded `ready\n` HTTP response. Preview Edge owns the
distinct ServerAuth leaf/key and returns that response only while both its
narrow database authority and authenticated Relay are ready. The Server and
Worker receive only the public readiness CA.

The template includes `preview` because the complete Beta workload set is now
rendered. The standalone Preview Owner process owns
the official `TunnelRegistry`, the TLS 1.3 mTLS Relay listener, and the downstream
Runner WSS endpoint in one lifecycle. Each Runner reconnect obtains a fresh
one-use registration from Runner Control; Owner redemption binds the certificate
fingerprint, exact current connection generation, durable Placement, and exact
`RunnerSession`. UUID-only lookup, caller-selected Placement, or deriving the
generation from a Preview request is forbidden. An old disconnect may remove only
its exact incarnation and cannot delete a newer binding. Capability activation
atomically includes `preview` in `OMNIGENT_SAAS_CAPABILITIES` and sets
`OMNIGENT_SAAS_PREVIEW_ADAPTER_FACTORY` to
`saas.production.preview_readiness:build_remote_tls_preview_readiness`; setting
the factory without the capability, or the capability without the factory,
fails configuration. Owner is deliberately `replicas: 1`, `strategy: Recreate`,
`omnigent.io/production-eligible=false`, and
`omnigent.io/production-blocker=preview-owner-singleton`: this preserves Beta
correctness but is a hard Production blocker until the registry is durable,
shared, and fenced. The Owner uses only the `saas_preview_owner` login; Edge
uses only `saas_preview_edge`. Neither authority is available to the Server,
Worker, or Runner.

The Beta singleton has one unique gateway instance ID, one registration token,
and distinct relay client/server leaves. Both leaves carry exactly
`spiffe://omnigent/preview-gateway/{gateway_instance_id}`; the client leaf is
ClientAuth, while the server leaf is ServerAuth and covers the exact rendered
headless Owner Service DNS. Before startup, the database must contain the matching
active gateway row with token hash, DNS name, port 9443, failure domain, and
certificate metadata. Owner renews that row every 15 seconds against the fixed
45-second database lease; failed initial or continuing CAS exits fail-closed.
Shutdown tombstones the incarnation, so replacement requires a fresh ID, token,
leaves, and active row rather than reviving the old identity. The dedicated
ServiceAccount has no API token, Role, or RoleBinding.

The authenticated browser API accepts exactly `run_id` plus the fixed
`preview_kind=static_web_v1`, with a required `Idempotency-Key`. It never accepts
or returns a Runner ID, connection generation, Worktree ID, fence, capability,
lease token, command, endpoint, or database credential. The server creates a
durable child Preview Run only from a succeeded source Run whose ChangeSet has a
committed checkpoint, then allocates a separately fenced readonly Worktree from
that checkpoint. The source Run remains terminal and its writer Worktree is not
held open. Create/status/stop are crash-replay safe; while materialization or
startup is pending the API returns `202`, and only a durable `ready` execution can
return the isolated Preview URL.

That URL carries a short-lived exchange bearer which the Edge consumes exactly
once by hash and exact host. Successful exchange creates an independent random
browser-session token in a `Secure`, `HttpOnly`, `SameSite` host-only cookie; the
original bearer is never copied into the cookie or a redirect. Every subsequent
request reauthorizes hash, host, execution, routing generation, Placement, and
Runner connection generation in PostgreSQL, rotates the session token under a
bounded grace window, and rejects replay, forged host, stale generation, or
revoked execution. Edge has no raw INSERT/UPDATE authority over Preview session
rows; its exchange, authorize, rotate, and revoke operations are narrow
`SECURITY DEFINER` functions with fixed `search_path` and no PUBLIC execute.

The first execution profile is the closed `static_web_v1` contract. A server-owned
child Run selects the fixed trusted module
`python -P -m saas.runner_adapter.static_web_preview` and fixed `dist/` directory;
browser input cannot supply argv, path, environment, or secret values. The
runtime never imports or executes Worktree code. It opens each path component
relative to a pinned directory descriptor with no-follow semantics, rejects
dotfiles, directory listings, symlinks, Range, oversized or changing files, uses
a deterministic closed MIME map, and emits fixed CSP/nosniff/no-store headers.
The checkout owner may retain OS write permission: the production invariant is
the exact durable readonly Worktree/checkpoint grant plus this static-only
reader, not filesystem mode alone.

These source and database contracts are necessary but are not rollout evidence.
Production admission still requires the rendered thirteen-login binding receipt,
fresh PostgreSQL 18 four-authority migration plus managed-superuser cluster
admission evidence, live cross-replica registration and disconnect probes,
authenticated browser exchange/replay E2E, NetworkPolicy packet probes,
rollback, and the stability window against the exact release SHA. A PostgreSQL
16 N-1 compatibility run cannot admit either Beta or Production.

## PostgreSQL CA handoff

The Beta PostgreSQL profile is dedicated CNPG PostgreSQL 18 with source CA Secret
`omnigent-postgres-ca` in namespace `omnigent-next-beta-data`. Kubernetes cannot
mount that Secret across namespaces. A controlled release step must copy only its public
`ca.crt` into the application namespace as `omnigent-saas-postgresql-ca`; never
copy a private key and never put the CA or any DSN in a ConfigMap. Private CA key
is never projected into any Pod: every public-only CA volume uses exact
`items: [{key: ca.crt, path: ca.crt}]` with mode 0400, so an accidentally added
`ca.key` or `tls.key` remains unmounted. Migration init
stages it as `/authority/postgresql-ca.crt`; Server, Worker/Runner Control, both
Runner agents, Preview Edge, and Preview Owner stage it as
`/runtime/postgresql-ca.crt`. Migration DSNs must include
`sslmode=verify-full&sslrootcert=/authority/postgresql-ca.crt`; all runtime DSNs
must include `sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt`.

## NetworkPolicy rendering

`kubernetes.network-policy.yaml` starts with namespace-wide ingress and egress
default-deny. DNS is limited to the labeled `kube-system` CoreDNS pods. Its source
production boundary is namespace `omnigent-data`; the trusted Beta renderer must
replace the one anchored textual value and exactly six semantic consumers with
`omnigent-next-beta-data`. PostgreSQL remains limited to selector
`cnpg.io/cluster=omnigent-postgres`, TCP 5432. Inter-service paths are exact:
Server to Worker readiness 9445; both Server and Worker to Preview Edge
readiness 8443; Runner agents to Runner Control 9444 and Preview Owner WSS 9442;
Preview Edge to Preview Owner mTLS 9443. Public ingress is a fail-closed
namespace/workload selector placeholder.

The live cluster currently uses Pod addresses in `10.42.x` and Service addresses
in `10.43.x`; the renderer must discover and verify the complete authoritative
CIDRs before replacing the corresponding release fields. Artifact and repository
addresses are not yet frozen. Therefore the NetworkPolicy source contains the
invalid sentinels `replace-with-artifact-endpoint-cidr` and
`replace-with-repository-endpoint-cidr`. Replace each with one reviewed exact
CIDR (or render multiple explicit rules); unresolved sentinels must fail API
validation. `0.0.0.0/0`, `::/0`, DNS-only public egress, and widening on resolution
failure are forbidden.

The migration Job is one indivisible four-authority operation with
`backoffLimit: 0`, `activeDeadlineSeconds: 900`, and
`ttlSecondsAfterFinished: 600`; a hung authority process fails the deadline and
a completed high-authority Pod is removed after the bounded evidence window.
The Worker init, running as UID 10001, creates `/health/state` with exact mode
0700 inside its shared writable memory volume. Startup/readiness/liveness execute
`omnigent-saas-worker-health` against
`/health/state/worker-health.json`. Runner Control startup/readiness use the
content-blind TLS 1.3 port 9445 verifier; only liveness uses TCP 9444.

The isolated Beta Runner profile is fixed at `max_concurrency=1`, one CPU, and
512 MiB per A/B outer Pod. The manifest cannot prove the node cgroup controller
state. Admission therefore also requires secret-free evidence from each real
rendered Pod showing its resolved cgroup has `pids.max=128`,
`memory.swap.max=0`, and `memory.oom.group=1`; absence, a different value, or a
host-only observation blocks Beta. No YAML annotation may substitute for that
receipt.

## Unclosed Run security boundaries

The manifests do not yet deploy the policy-required two-replica egress proxy.
Consequently `runner_egress_proxy_only` has no live bypass-denial evidence, and
any Production Run that can initiate external network traffic remains blocked.
Exact proxy identity, NetworkPolicy redirection, destination policy, failover,
direct-egress denial, and authenticated packet evidence are required before that
gate can close.

The Runner's `/runtime/secret-provider` is only an owner-only empty directory; it
is not a production secret provider. Secret-bearing Runs remain blocked until an
isolated provider supplies per-Run, tenant-scoped, short-lived material with
audited issuance, revocation, cleanup, crash recovery, and log/artifact leak
tests. A mounted directory or a successful non-secret Run is not evidence for
this boundary.

## Trusted release renderer

`omnigent-saas-render-kubernetes-release` accepts one canonical, secret-free
public release spec and the exact four source manifests. SHA fields are
`sha256:<64 lowercase hex>` in the spec and Pod annotations; runtime SHA
environment values use the same hex without the prefix. Each Runner is bound to
its ID, generation, slot, exact-one `primary` repository profile, non-secret
credential revision, sealed spec/bindings/receipt hashes, and immutable Secret
names. The fleet public Secret suffix derives from trust-pins SHA. A repository
spec Secret suffix derives from the canonical release-incarnation/slot/spec-SHA
tuple, and the credential Secret suffix derives from the non-secret credential
revision. Stage permits only fleet admission-receipt document/signature fields
and artifact receipt fields to be pending; environment attestation, public keys,
fleet/context/pins, and all repository hashes must already be nonzero. Final
permits no pending or sentinel input.

Stage output makes every long-running Deployment zero replicas and leaves only
the bounded migration/artifact Jobs runnable. Final output restores only the
reviewed source replica counts, changes A/B from zero to one, and removes the
fleet admission blocker after all bound receipt checks. Both modes emit a
canonical `release-render-evidence.json`; its independently calculated SHA256 is
the release evidence handle. The renderer never reads or rewrites a Secret
value.

## Trusted namespace renderer

`omnigent-saas-render-next-beta` reads exactly the four source YAML files and
rejects Secret resources, symlinks, extra YAML, pre-rendered namespaces, malformed
service DNS, residual source namespace references, non-empty output directories,
and any semantic change outside resource `metadata.namespace`, exact Kubernetes
service-DNS suffixes, and the fixed external database namespace projection. It
fixes `omnigent -> omnigent-next-beta` and the exact
`omnigent-data -> omnigent-next-beta-data` database boundary. The schema-v2
evidence records both database namespaces and the required replacement count of
six. It does not replace image,
revision, CIDR, credential, Secret-name, or any other release placeholder.

Each successful run writes four mode-0600 manifests and a canonical,
secret-free `namespace-render-evidence.json`. Stdout contains only its SHA256,
the rendered-set SHA256, count, and status. The evidence hash must be recorded
with the release; never infer success merely from files appearing in the output
directory.

## Staged K3s procedure

Work from a private release directory and never put credential values in shell
arguments. The following commands name files only:

```sh
umask 077
RELEASE_ROOT=/secure/omnigent-release
SOURCE_DIR="${RELEASE_ROOT}/source"
STAGE_DIR="${RELEASE_ROOT}/rendered-stage"
FINAL_DIR="${RELEASE_ROOT}/rendered-final"
OMNIGENT_NAMESPACE=omnigent-next-beta
export RELEASE_ROOT SOURCE_DIR STAGE_DIR FINAL_DIR OMNIGENT_NAMESPACE
install -d -m 0700 "${RELEASE_ROOT}" "${SOURCE_DIR}"
cp saas/deployment/server/kubernetes.migration.yaml "${SOURCE_DIR}/"
cp saas/deployment/server/kubernetes.artifact-admission.yaml "${SOURCE_DIR}/"
cp saas/deployment/server/kubernetes.network-policy.yaml "${SOURCE_DIR}/"
cp saas/deployment/server/kubernetes.production.yaml "${SOURCE_DIR}/"

# The canonical public stage spec already contains nonzero fleet/context/pins,
# signed environment-attestation hashes, and per-slot sealed-rehearsal repository
# spec/bindings/receipt hashes. Only the fleet promotion receipt and artifact
# receipt fields are pending. The renderer performs both release binding and the
# trusted namespace projection; it sets every long-running Deployment to zero.
STAGE_SPEC="${RELEASE_ROOT}/public-release-stage.json"
omnigent-saas-render-kubernetes-release \
  --spec-file "${STAGE_SPEC}" \
  --source-dir "${SOURCE_DIR}" \
  --output-dir "${STAGE_DIR}" \
  > "${RELEASE_ROOT}/release-render-stage-summary.json"
STAGE_EVIDENCE_SHA256="sha256:$(
  sha256sum "${STAGE_DIR}/release-render-evidence.json" | awk '{print $1}'
)"
jq -e --arg evidence "${STAGE_EVIDENCE_SHA256}" \
  '.status == "pass" and .mode == "stage" and .manifest_count == 4 and \
   .receipt_state == "pending" and .evidence_sha256 == $evidence' \
  "${RELEASE_ROOT}/release-render-stage-summary.json"
sha256sum "${STAGE_DIR}/release-render-evidence.json" \
  > "${RELEASE_ROOT}/release-render-stage-evidence.sha256"
rg -n 'image: .*@sha256:[0-9a-f]{64}$' "${STAGE_DIR}"/*.yaml
```

Create the four authority Secrets from already protected files after the
external identity bootstrap has succeeded:

```sh
kubectl -n "${OMNIGENT_NAMESPACE}" create secret generic omnigent-saas-principal-operator \
  --from-file=value=/secure/authority/principal-operator-url
kubectl -n "${OMNIGENT_NAMESPACE}" create secret generic omnigent-saas-database-owner \
  --from-file=value=/secure/authority/database-owner-url
kubectl -n "${OMNIGENT_NAMESPACE}" create secret generic omnigent-saas-official-owner \
  --from-file=value=/secure/authority/official-owner-url
kubectl -n "${OMNIGENT_NAMESPACE}" create secret generic omnigent-saas-control-plane-owner \
  --from-file=value=/secure/authority/saas-owner-url
kubectl apply --server-side --dry-run=server \
  -f "${STAGE_DIR}/kubernetes.migration.yaml"
kubectl apply --server-side -f "${STAGE_DIR}/kubernetes.migration.yaml"
kubectl -n "${OMNIGENT_NAMESPACE}" wait --for=condition=complete --timeout=30m \
  job/omnigent-saas-postgresql-migration
```

The completed Job is only a candidate receipt. Do not create the receipt Secret
yet. From a separate short-lived, audited managed-superuser channel, execute the
packaged `saas/control_plane/postgresql_runner_agent_cluster.psql` against this
exact Beta database after confirming its packaged SQL hash. That external
channel owns admin authentication; these manifests and the four-authority Job
must never receive or transport its credential. The wrapper must finish its
first-error-stopping transaction, and the evidence capture must show the exact
post-transaction rows from these secret-free checks:

```sql
SELECT current_setting('server_version_num')::integer / 10000 AS server_major;
SELECT name, setting, context, source, pending_restart
FROM pg_settings
WHERE name IN ('max_notify_queue_pages', 'max_prepared_transactions')
ORDER BY name;
SELECT count(*) AS prepared_xacts FROM pg_prepared_xacts;
```

The only admissible result is server major `18`,
`max_notify_queue_pages=64`, `max_prepared_transactions=0`, both rows with
`context=postmaster`, `source=configuration file`, and
`pending_restart=false`, and `prepared_xacts=0`. The external release ledger
must also retain the wrapper and included SQL SHA256, CNPG Cluster UID, image
digest, routine-denial assertion result, operator identity, and execution time.
Hash that secret-free record and bind its digest to the release; never retain a
DSN, token, certificate key, or password in it. Any mismatch or missing evidence
stops the release before the application namespace receives a runtime Secret.

Only after that managed-superuser gate passes, persist and inspect the
secret-free candidate receipt before creating its runtime Secret. Never pipe the
log through a JSON extractor: the file itself must parse as the single document,
otherwise the run is rejected. Freeze the receipt SHA256 and the external
cluster-admission evidence SHA256 together in the release evidence ledger before
creating the Kubernetes Secret below.

```sh
umask 077
kubectl -n "${OMNIGENT_NAMESPACE}" logs job/omnigent-saas-postgresql-migration \
  > /secure/omnigent-release/postgresql-migration-receipt.json
jq -e '.status == "pass" and (.phases | index("state:verified")) and \
  (.service_role_bindings_sha256 | test("^[0-9a-f]{64}$")) and \
  (.product_revision | test("^[0-9a-f]{40}$"))' \
  /secure/omnigent-release/postgresql-migration-receipt.json
kubectl -n "${OMNIGENT_NAMESPACE}" create secret generic omnigent-saas-migration-receipt \
  --from-file=value=/secure/omnigent-release/postgresql-migration-receipt.json \
  --dry-run=client -o yaml | kubectl apply -f -
```

Provision these runtime Secrets from protected files before the production
manifest is applied:

- `omnigent-saas-runtime-database`
- `omnigent-saas-authenticator-database`
- `omnigent-saas-app-database`
- `omnigent-saas-governance-database`
- `omnigent-saas-public-api-database`
- `omnigent-saas-dispatcher-database`
- `omnigent-saas-executor-database`
- `omnigent-saas-runner-agent-a-database-g1` and
  `omnigent-saas-runner-agent-b-database-g1`, each containing only a `value` file
  with a TLS DSN for its exact canonical
  `runner_<runner_uuid_without_hyphens>_g1` LOGIN. Each LOGIN inherits only
  `saas_runner_agent`; it is never shared with the central executor authority or
  the other Runner incarnation.
- `omnigent-saas-application-keys` with keys `api-credential-pepper`,
  `cursor-hmac-key`, `idempotency-hmac-key`, `context-snapshot-key`, and the
  independent `preview-exchange-hmac-key`
- one immutable, credential-digest-scoped Server artifact Secret (the template
  name is `omnigent-artifact-creds-replace-credential12`) with a single
  `credentials` file and the exact non-default profile named by
  `OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE`; it is mounted only by Server
  and the one-shot artifact admission Job
- one immutable, release-incarnation-scoped artifact admission receipt Secret
  (the template name is `omnigent-artifact-receipt-replace-release12`) created
  only after the admission Job log is validated and hashed
- two immutable, per-incarnation Runner recovery Secrets (template names
  `omnigent-runner-a-recovery-replace-g1-v1` and
  `omnigent-runner-b-recovery-replace-g1-v1`) with one `credentials` file each.
  Each profile, object prefix, Runner UUID, connection generation, and SHA256
  revision must be rendered together; no field may be shared between identities
- `omnigent-saas-runner-control-tls` with keys `ca.crt`, `tls.crt`, and
  `tls.key`; the server leaf must be ServerAuth for the internal Service name,
  while Runner ClientAuth leaves use exactly one
  `spiffe://omnigent/runner/{uuid}` URI SAN and are approved separately for
  purpose `runner_control`
- `omnigent-saas-runner-control-ca` with only the public `ca.crt` used by the
  Server to authenticate the internal content-blind readiness listener
- `omnigent-saas-runner-agent-a-identity` and
  `omnigent-saas-runner-agent-b-identity`, each with `ca.crt`, one ClientAuth
  `tls.crt`, `tls.key`, and its matching one-time `connection-token`; each
  Deployment's explicit Runner ID and generation come from the same registration
  response
- per-slot immutable repository provisioning Secrets derived from release
  incarnation, slot, and canonical spec SHA (template names
  `omnigent-saas-runner-a-repository-provisioning-replace-repospec12` and the B
  counterpart), each containing only `repository-provisioning.json`; this Beta
  profile's spec must set `expected_binding_keys` to exactly `["primary"]`
- per-slot immutable repository credential Secrets derived from the non-secret
  credential revision (template names
  `omnigent-saas-runner-a-repository-credentials-replace-repocreds12` and the B
  counterpart), each projecting only `primary.credential`. Both repository
  Secrets are init-only and are never mounted by the Runner main container
- `omnigent-saas-preview-runner-tunnel-ca` with only the public `ca.crt` used by
  both Runner tunnel clients; no Preview private key is mounted by a Runner
- `omnigent-saas-preview-edge-database`
- `omnigent-saas-preview-owner-database`
- `omnigent-saas-preview-owner-registration-replace-owner12` with one owner-only
  `registration-token` matching the durable Preview gateway incarnation
- `omnigent-saas-preview-relay-client-tls` with the Edge's `ca.crt`, `tls.crt`,
  and `tls.key`
- `omnigent-saas-preview-owner-relay-client-tls-replace-owner12` with the
  Owner's `ca.crt`, `tls.crt`, and `tls.key`
- `omnigent-saas-preview-owner-relay-server-tls-replace-owner12` with the TLS 1.3 ServerAuth
  leaf and private key used only by Preview Owner; its SANs cover the rendered
  Owner Service names for ports 9442 and 9443
- `omnigent-saas-preview-readiness-tls` with a ServerAuth `tls.crt` for
  `omnigent-saas-preview-edge.omnigent.svc.cluster.local` and its `tls.key`
- `omnigent-saas-preview-readiness-ca` with only the public `ca.crt` used by the
  Server and Worker content-blind Preview readiness adapters
- `omnigent-saas-postgresql-ca` with only `ca.crt`, copied by the controlled
  release process from `omnigent-next-beta-data/omnigent-postgres-ca`

Every DSN Secret uses a single `value` key. Each URL must name one distinct
login, target the same receipt-bound `omnigent_next_beta` database at
`omnigent-postgres-rw.omnigent-next-beta-data.svc.cluster.local`, require
`sslmode=verify-full`, and must not contain `role` or libpq `options` query
parameters. Runtime URLs pin
`sslrootcert=/runtime/postgresql-ca.crt`; migration authority URLs pin the
corresponding `/authority` path.

Before the Server is admitted, create the small immutable readiness canary at
the exact configured `OMNIGENT_SAAS_ARTIFACT_READINESS_KEY`, record the SHA256 in
`OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256`, and verify HEAD plus bounded GET with
the Server profile. The canary is release infrastructure, not tenant data; the
bucket policy must deny mutation after creation. A separate pre-deployment
artifact admission probe must then use a unique release-scoped object in each of
the admission, bare file-ID, bare agent bundle, and `executor_storage` key spaces
to perform the same provider-compatible PUT call as the official S3 wrapper,
HEAD, exact bounded GET/hash, and an accepted logical DELETE request.
A credential whose path policy admits only the probe namespace, or a read-only
credential that can read the canary but cannot complete every CRUD probe, must
fail rollout.
The Job deliberately does not HEAD after DELETE: AWS S3 returns 403 rather than
404 for a missing object when the principal correctly lacks `ListBucket`, and a
versioned bucket may create a delete marker rather than physically erase a
version. Successful CRUD therefore proves required positive access and an
accepted logical delete only; it does not prove current invisibility, physical
erasure, absence of `ListBucket`, cross-prefix, overwrite, or unrelated-object
access. An independent evidence principal must verify current-key invisibility,
version/delete-marker retention, and eventual garbage collection without sharing
its list/version authority with Server or the admission Job. External
IAM/bucket policy must restrict Server and admission to the four documented
business key spaces plus the one exact immutable readiness-canary object. The
canary permits only HEAD/GET; the business keys permit only the reviewed
PUT/HEAD/GET/DELETE operations. The policy must deny bucket listing, overwrite of
the canary, and every unrelated prefix, and bind the exact credential revision.
Production Admission must include independent signed bucket-policy,
IAM-analyzer, and post-delete visibility/version evidence; the JSON CRUD receipt
must not be presented as least-privilege or physical-deletion evidence.
Credential values stay in the protected file and must never be passed as command
arguments or environment variables.

Render and run the separate artifact admission Job before applying any
long-running workload. The product and source revisions must be identical, the
installed wheel lineage is checked before the first S3 request, and the release
incarnation must be freshly generated for this rollout. Its log must be exactly
one JSON document. Freeze that receipt as release evidence; a rerun needs a fresh
incarnation, versioned Job/ConfigMap/Secret names, Job, and receipt rather than
editing the prior record. The Kubernetes receipt is an operator-authenticated
Beta rollout handoff, not production evidence by itself: final Production
Admission must additionally consume an independently signed DSSE receipt from
the protected evidence workflow.

```sh
# The renderer exports these public, exact facts from the rendered manifests:
# OMNIGENT_ARTIFACT_JOB_NAME, OMNIGENT_ARTIFACT_RECEIPT_SECRET,
# OMNIGENT_PRODUCT_REVISION, OMNIGENT_IMAGE_DIGEST,
# OMNIGENT_RELEASE_INCARNATION, OMNIGENT_ARTIFACT_STORE_URI_SHA256,
# OMNIGENT_ARTIFACT_ENDPOINT_URL_SHA256, OMNIGENT_ARTIFACT_REGION, and
# OMNIGENT_ARTIFACT_CREDENTIAL_REVISION.
: "${OMNIGENT_ARTIFACT_JOB_NAME:?renderer did not export the Job name}"
: "${OMNIGENT_ARTIFACT_RECEIPT_SECRET:?renderer did not export the receipt Secret name}"
kubectl apply --server-side --dry-run=server \
  -f "${STAGE_DIR}/kubernetes.artifact-admission.yaml"
kubectl apply --server-side \
  -f "${STAGE_DIR}/kubernetes.artifact-admission.yaml"
kubectl -n "${OMNIGENT_NAMESPACE}" wait --for=condition=complete --timeout=5m \
  "job/${OMNIGENT_ARTIFACT_JOB_NAME}"
kubectl -n "${OMNIGENT_NAMESPACE}" logs "job/${OMNIGENT_ARTIFACT_JOB_NAME}" \
  > /secure/omnigent-release/artifact-admission-receipt.json
jq -e --arg product "${OMNIGENT_PRODUCT_REVISION}" \
  --arg image "${OMNIGENT_IMAGE_DIGEST}" \
  --arg incarnation "${OMNIGENT_RELEASE_INCARNATION}" \
  --arg store "${OMNIGENT_ARTIFACT_STORE_URI_SHA256}" \
  --arg endpoint "${OMNIGENT_ARTIFACT_ENDPOINT_URL_SHA256}" \
  --arg region "${OMNIGENT_ARTIFACT_REGION}" \
  --arg credential "${OMNIGENT_ARTIFACT_CREDENTIAL_REVISION}" \
  '.schema_version == 1 and .status == "pass" and \
  .product_revision == $product and .source_revision == $product and \
  .image_digest == $image and .release_incarnation == $incarnation and \
  .artifact_store_uri_sha256 == $store and \
  .artifact_endpoint_url_sha256 == $endpoint and \
  .artifact_region == $region and .credential_revision == $credential and \
  .verified_key_spaces == ["admission","file_id","agent_bundle","executor_storage"] and \
  .operations == ["put","head","get_hash","delete"]' \
  /secure/omnigent-release/artifact-admission-receipt.json
OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION="sha256:$(
  sha256sum /secure/omnigent-release/artifact-admission-receipt.json |
    awk '{print $1}'
)"
export OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION
kubectl -n "${OMNIGENT_NAMESPACE}" create secret generic "${OMNIGENT_ARTIFACT_RECEIPT_SECRET}" \
  --from-file=value=/secure/omnigent-release/artifact-admission-receipt.json \
  --dry-run=client -o json > /secure/omnigent-release/artifact-receipt-secret.json
jq '.immutable = true' /secure/omnigent-release/artifact-receipt-secret.json \
  > /secure/omnigent-release/artifact-receipt-secret-immutable.json
kubectl apply --server-side \
  -f /secure/omnigent-release/artifact-receipt-secret-immutable.json
```

Only after the exact artifact and Runner-fleet receipt bytes and signatures have
been independently verified and hashed may the trusted renderer produce a final
manifest. The canonical public final spec binds those hashes, their public-key
fingerprints and epoch, and every nonzero repository rehearsal hash. It contains
no Secret value. The renderer rejects a pending receipt, all-zero hash, source
drift, extra field, or stale resource-name derivation; it is the only component
authorized to restore long-running replica counts.

```sh
FINAL_SPEC="${RELEASE_ROOT}/public-release-final.json"
omnigent-saas-render-kubernetes-release \
  --spec-file "${FINAL_SPEC}" \
  --source-dir "${SOURCE_DIR}" \
  --output-dir "${FINAL_DIR}" \
  > "${RELEASE_ROOT}/release-render-final-summary.json"
FINAL_EVIDENCE_SHA256="sha256:$(
  sha256sum "${FINAL_DIR}/release-render-evidence.json" | awk '{print $1}'
)"
jq -e --arg evidence "${FINAL_EVIDENCE_SHA256}" \
  '.status == "pass" and .mode == "final" and .manifest_count == 4 and \
   .receipt_state == "bound" and .evidence_sha256 == $evidence' \
  "${RELEASE_ROOT}/release-render-final-summary.json"
sha256sum "${FINAL_DIR}/release-render-evidence.json" \
  > "${RELEASE_ROOT}/release-render-final-evidence.sha256"
rg -n '00000000000000000000000000000000|replace[._-]' \
  "${FINAL_DIR}" && exit 1
```

Then validate and apply without exposing a host port:

```sh
kubectl apply --server-side --dry-run=server \
  -f "${FINAL_DIR}/kubernetes.network-policy.yaml"
kubectl apply --server-side --dry-run=server \
  -f "${FINAL_DIR}/kubernetes.production.yaml"
kubectl apply --server-side -f "${FINAL_DIR}/kubernetes.network-policy.yaml"
kubectl apply --server-side -f "${FINAL_DIR}/kubernetes.production.yaml"
kubectl -n "${OMNIGENT_NAMESPACE}" rollout status deployment/omnigent-saas-worker --timeout=15m
kubectl -n "${OMNIGENT_NAMESPACE}" rollout status deployment/omnigent-saas-server --timeout=15m
kubectl -n "${OMNIGENT_NAMESPACE}" rollout status deployment/omnigent-saas-runner-agent-a --timeout=15m
kubectl -n "${OMNIGENT_NAMESPACE}" rollout status deployment/omnigent-saas-runner-agent-b --timeout=15m
kubectl -n "${OMNIGENT_NAMESPACE}" rollout status deployment/omnigent-saas-preview-edge --timeout=15m
kubectl -n "${OMNIGENT_NAMESPACE}" rollout status deployment/omnigent-saas-preview-owner --timeout=15m
kubectl -n "${OMNIGENT_NAMESPACE}" get service omnigent-saas-runner-control \
  -o jsonpath='{.spec.type}{" "}{.spec.ports[0].port}{"\n"}'
kubectl -n "${OMNIGENT_NAMESPACE}" get service omnigent-saas-server \
  -o jsonpath='{.spec.type}{" "}{.spec.ports[0].port}{"\n"}'
curl --fail --silent --show-error https://next.jxhh.com/saas/readyz
curl --fail --silent --show-error https://next.jxhh.com/saas/version | jq .
```

The live `next.jxhh.com` TLS edge is the GitOps-managed
`omnigent-fast-track-ingress` HAProxy NodePort 30443 with two replicas. After
side-path authenticated Tenant/Run/Runner/Preview E2E passes against the new
ClusterIP backends, traffic changes only through a reviewed desired-state HAProxy
backend commit. Rollback is the preceding backend commit. This application
template never takes over edge TLS. Rollback leaves the dedicated Beta CNPG
Cluster and retained PVCs quarantined; it never drops the database and never
changes the live `omnigent-data` ACL projection.

The release is still not production-admitted at this point. In addition to
authenticated Tenant/Run/Runner/Preview E2E, rollback, and stability-window
evidence, Production requires durable multi-owner Preview fencing, observed
backup/PITR/restore, external PKI lifecycle evidence, exact IAM/CIDR evidence,
the policy-required two-replica egress proxy plus observed bypass denial, and
reviewed NLB/HAProxy/DNS routing governance. Those are explicit blockers, not
post-launch follow-ups.
