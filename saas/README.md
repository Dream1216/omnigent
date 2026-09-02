# Omnigent SaaS downstream boundary

This directory owns the commercial SaaS control plane and the permanent
compatibility layer around the official Omnigent runtime. The official runtime
must not import this package; dependencies only flow from `saas` to `omnigent`.

P0 establishes executable controls that stay independent of feature claims:

1. `upstream-baseline.json` pins the verified official source, schema, runner
   protocol, adapter contract, and source-intrusion budgets.
2. `compatibility/runtime_partition.py` derives a fail-closed RuntimeContext
   from trusted Placement, Partition, Identity Alias, and Resource Binding
   records, then projects only the physical workspace into Omnigent.
3. `scripts/check_upstream_delta.py` produces `upstream-delta-report.json` and
   blocks forbidden Native Bridge/Harness changes, reverse dependencies, stale
   lineage, or an exceeded patch/LOC/file budget.
4. `scripts/check_patch_queue.py` replays every active patch, in order, against
   the pinned official revision and requires complete coverage of direct
   `omnigent/` changes.
5. `acceptance/p0-p6-evidence.json` keeps implementation evidence, pending
   acceptance gates, and the current `NO-GO` decision machine-readable. CI
   rejects a premature phase completion or production `GO`.
6. `production/baseline.json` turns the eleven production ADRs, seven service
   ownership records, six SLOs, T0-T2 RPO/RTO proposals, STRIDE threats, and
   risk register into validated data. Its strict mode stays blocked until the
   required human approvals, live dashboards, and recovery drills exist.
7. `supply_chain/release-policy.json` defines digest-pinned build materials,
   repeat-build comparison, source/schema/adapter image labels, dual SBOM,
   maximum SLSA provenance, keyless signature, zero Critical/High admission,
   zero denied/unknown license admission, exact protected workflow/OIDC subject,
   signature subject and transparency proof, OSS/SaaS regression, immutable
   registry receipt, one-hour digest-only canary, and bounded N-1 rollback. Its
   strict v2 verifier rejects stale scans, reused approvers, canonical-record
   tampering, repository escapes, and symlinked evidence. The candidate workflow
   builds twice without publishing; it cannot be mistaken for signed production
   evidence.

The active Wave 1 product slice on `codex/wave1-upstream-onboarding` extends the
self-service authority into a fail-closed backend activation chain without
treating code contracts as production Provider evidence:

- anonymous registration validates a deployment-owned plan/region catalog,
  normalizes the requested Tenant and default Space, consumes a construction-sealed
  database-authoritative rate limit shared by every replica, and persists preallocated
  product identifiers behind dedicated `saas_registration` RLS policies; storage
  failure rejects registration, resend and verification before domain writes;
- verification secrets are high-entropy, hash-only, expiring, single-generation
  credentials. Email address and raw token leave the transaction only inside an
  AES-GCM Outbox envelope bound to the immutable event ID; stale generations are
  suppressed before delivery;
- public registration and resend responses deliberately omit replay, expiry,
  identity-conflict, and internal lifecycle facts. Verification performs the
  expensive password KDF only after the challenge is found and locked, and only
  the original receipt may replay a consumed challenge;
- successful verification atomically creates the Global User, password Identity
  Connection and Password Credential, then emits durable Tenant-provisioning
  intent. The coordinator creates only a `provisioning` Tenant, `suspended`
  default Space and Owner memberships under the separate `saas_onboarding` role;
- a hash-linked, PII-rejecting event stream and a staged onboarding Saga preserve
  the audit and recovery boundary. Reviewed Plan/Trial terms, Placement and
  Provider Binding identity, Runtime Partition/Alias, default Project/Quota,
  activation and first normal Run admission are frozen and replayable;
- poison Outbox events use content-blind error facts, bounded retry and an
  immutable Quarantine receipt. A dedicated actor-owned status authority exposes
  only the customer's onboarding projection;
- candidate schema revision `p0s000000011` extends the forced-RLS control plane
  through exact dispatch/profile binding, Preview execution sessions, and
  per-Runner-incarnation database authority. The preceding approved p0s7 record
  remains immutable history; this successor requires a new decision and
  evidence flow before it can be accepted. The direct Runner DML projection is
  isolated-Beta-only: cross-profile secret/isolation forgery, capability-action
  substitution, disabled/non-FORCE RLS, cross-database reachability, and catalog
  drift must fail closed before Beta. Enterprise Production Admission further
  requires narrow RPCs or transition triggers for every Runner-mutated
  Worktree, quota, Preview, and Outbox state change.

The production Runtime seam is `ProductionRuntimePartitionAdapter`. It freezes
the non-secret Provider type/revision/hash before any external effect, keeps old
bindings available for in-flight replay and compensation, and requires a
verified signed Receipt. `PostgresqlRuntimeProviderOperationJournal` writes the
atomic effect fence before transport execution and replays only a fully verified
response after process restart or acknowledgement loss. Its engine must be a
one-purpose LOGIN inheriting only `saas_runtime_provider_journal`; owner,
superuser, assumed-role, direct-ACL and catalog-drift connections fail startup.

This remains a development candidate, not P0 completion or production `GO`.
Production still requires a deployment-owned Provider transport, short-lived
non-ambient credential authority, KMS/HSM-backed Receipt verifier, retained
historical bindings, anonymous browser E2E, Staff Quarantine operations, protected
CI/approval and signed deployment evidence. Enterprise SAML/OIDC/domain/JIT and
MFA/recovery, the full Staff administration product, and Operations Center remain
separate P0 tracks.

The first P1 slice adds an independent control-plane schema and migration for
Global User, Tenant, Space, versioned Membership, Runtime Placement, Runtime
Partition, Identity Alias, and Resource Binding records. Its server-side
resolver:

- re-reads active Tenant and Space memberships before entering the runtime;
- rejects membership-version changes after a RequestContext is issued;
- resolves Placement, physical partition, identity alias, and revision metadata
  only from trusted database records;
- rejects unapproved source/schema/adapter revisions and `workspace_id = 0`;
- keeps project-scoped bindings closed until the P2 Project Authorizer exists.

The second P1 slice adds SaaS-owned Identity Connection, revocable Auth
Session, email-bound Membership Invitation, and transactional control-plane
Outbox records. `MembershipLifecycleService`:

- treats `(issuer, subject)` as the authentication identity and uses verified
  email only for fail-closed invitation matching;
- stores only SHA-256 digests of high-entropy session and invitation secrets;
- atomically consumes one-time invitations and creates Tenant/Space
  memberships with a persist-first Outbox event;
- applies compare-and-swap Membership updates, atomically increments the
  Global User security version, and revokes active Auth Sessions in the same
  transaction;
- rejects Owner changes, admin elevation, and member removal until their
  dedicated high-risk workflows provide fresh authentication, impact preview,
  resource transfer, and audited approval.

The third P1/P2 slice completes the first deployable identity and governance
boundary without changing the official server application:

- `SaasAuthProvider` plugs opaque, revocable sessions into the official
  `AuthProvider` interface; `SaasAuthContextMiddleware` validates HttpOnly
  Cookie or Bearer credentials, browser Origin/CSRF, current security version,
  Tenant/Space membership, runtime allocation, and runtime identity alias;
- Identity Connections never merge users by email. Provider callbacks must
  construct a trusted `VerifiedIdentityAssertion`; the public HTTP surface does
  not accept provider assertions directly;
- Password Credentials use Argon2id, a unique verified login email, credential
  versions, constant-work unknown-user verification, bounded lockout, and
  all-session revocation after enrollment or rotation;
- `OutboxDispatcher` leases events with PostgreSQL `FOR UPDATE SKIP LOCKED`,
  publishes outside the database transaction, acknowledges by claim token, and
  provides at-least-once retry with exponential backoff. Consumers must
  deduplicate by immutable event ID. Public idempotency tokens are converted to
  opaque `Tenant + key` or `Global User + key` digests before persistence, so
  equal caller-selected keys in different security scopes cannot collide;
- Owner transfer locks and compare-and-swaps both memberships, requires fresh
  authentication and reason, writes an audit record, and revokes both users'
  sessions in one transaction;
- member removal requires a short-lived, trusted resource-impact snapshot and
  re-collects every fact before execution. It fails closed when the impact
  provider is absent, the member is an Owner, blockers exist, or facts changed.
  Tenant removal also logically removes active Space memberships;
- all 50 protected control-plane tables use `ENABLE` and `FORCE ROW LEVEL
  SECURITY` with transaction-local server-chosen Actor/Tenant/Space values.
  The packaged role bootstrap separates `saas_app`,
  `saas_authenticator`, `saas_governance`, `saas_dispatcher`,
  `saas_webhook_dispatcher`, and break-glass `saas_platform`; none has
  `BYPASSRLS`.

The fourth P1 slice closes the Context Shell and bounded control-plane
degradation implementation:

- `GET /saas/context/scopes` enumerates only the authenticated actor's active
  logical Tenant/Space memberships. PostgreSQL SELECT-only actor policies make
  this work without a client-chosen Tenant RLS context and do not broaden any
  write policy. The API and browser never return Placement, physical workspace,
  Runtime Alias, or database routing facts;
- `POST /saas/context/snapshots` re-resolves current membership and allocation
  state, then issues an opaque AES-GCM-encrypted and HMAC-signed snapshot bound
  to the raw Auth Session digest. It includes security/membership/policy,
  resource, Partition, Placement, Binding Generation, source revision, and
  adapter contract facts and can never live longer than 60 seconds;
- replicas share a rotatable key ring rather than process memory. While the
  control plane is healthy, every snapshot-backed request revalidates the Auth
  Session, Membership versions, Placement, Partition, Binding Generation, and
  runtime lineage, so revocation is immediate;
- dependency degradation is opt-in per exact GET/HEAD path. Only those
  low-risk reads may consume an unexpired snapshot. New login, scope selection,
  Mutation, WebSocket, new Run, Secret, export, member, billing, support, and
  unlisted reads fail closed with a stable unavailable result;
- Context Shell changed from free-form Tenant/Space IDs to a server-populated
  selector. The resulting snapshot is held only in page memory and exposes no
  physical runtime selectors;
- forced RLS now includes a separate Platform-only Runtime Placement mutation
  policy. This fixes provisioning after `FORCE ROW LEVEL SECURITY` without
  granting Placement writes to application, authentication, governance, or
  dispatch roles.

The P2 implementation adds a Project-isolated authorization and runtime-data
boundary:

- a versioned permission catalog plus immutable Tenant, Space, and Project
  roles. Tenant/Space ownership and administration do not imply Project content
  access; the Project `manage` role is deliberately content-blind;
- a server-side `ProjectAuthorizer` combines active scope snapshots, Project
  visibility, Project membership, and exact Resource Grants. Enforce and
  Shadow decisions are persisted with policy and Project authorization
  versions;
- Project membership and Resource Grant create/replace/revoke operations are
  idempotent, enforce delegation limits and last-Project-Owner invariants,
  increment one authorization version, and persist an Outbox event in the same
  transaction;
- Runtime Binding creation/retirement validates Project authorization,
  Placement/Partition generations, approved runtime/source/schema/adapter
  lineage, canonical non-default physical workspace keys, and duplicate active
  bindings. The durable cross-database Saga performs the same target validation
  before persisting intent or invoking the official runtime, resumes after
  crashes, compensates orphaned resources, and records operator-review failures;
- `OmnigentStoreAdapter` is the permanent compatibility boundary. It validates
  the reviewed adapter contract and Runtime generations, binds the official
  workspace ContextVar, and injects transaction-local Runtime RLS context into
  every official managed Store session through one generic upstream hook;
- `runtime_rls` drift-checks all 17 official `workspace_id` tables against both
  ORM metadata and the target database before installing paired permissive and
  restrictive PostgreSQL policies with `ENABLE` and `FORCE ROW LEVEL SECURITY`.
  Missing context returns no rows, cross-partition writes fail, unmanaged
  policies block deployment, and an explicit uninstall path supports rollback;
- the Project Admin API exposes the permission catalog, Project metadata and
  visibility, memberships, Resource Grants, access simulation, and Binding
  lifecycle. Every mutation maps to a registered permission and stable
  idempotency contract.

The official `create_app` already accepts an injected AuthProvider and extra
routers. Build `SaasHttpIntegration`, then pass it to
`create_omnigent_saas_app` in `saas.application`. The downstream composition
root injects the SaaS AuthProvider and `/saas` router, installs the context
middleware before serving, and rejects a competing AuthProvider or duplicate
SaaS route prefix. An integration test logs in through the SaaS Cookie and
accesses the official `/v1/me` route on the real official application factory.
This keeps HTTP authentication entirely in the downstream boundary and adds no
new official-source patch.

The production Outbox loop is runnable as `python -m saas.outbox_worker`. It
requires `OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL` to identify a real LOGIN
role that inherits only `saas_dispatcher`, and
`OMNIGENT_SAAS_OUTBOX_PUBLISHER=module:attribute` to identify an idempotent
publisher object, class, or zero-argument factory. Startup rejects a
superuser, `BYPASSRLS`, table owner, assumed role, another SaaS service role,
non-Outbox table access, or unsafe Outbox grants. SIGTERM/SIGINT drains the
current bounded cycle and returns worker counters; transient infrastructure
failures back off without losing durable leases.

Self-service onboarding publishers must be built with
`create_tenant_onboarding_composition` from `saas.onboarding_composition` and
export the returned `TenantOnboardingComposition` as the configured
`module:attribute`. The factory requires separate Registration, Onboarding, and
Execution Session factories plus the reviewed Plan, envelope, rate-limit,
email, and Runtime adapters; it always injects `TenantOnboardingWorkflow` into
`OnboardingOutboxPublisher`. The production loader rejects a raw
`OnboardingOutboxPublisher`, so `onboarding.billing.requested` cannot enter an
infinite `outbox_route_unavailable` retry because Workflow wiring was omitted.

The first customer Run remains a normal `ExecutionControlPlane` admission. Use
`TenantOnboardingComposition.execution_adapter(...).admit_first_run(...)` for
the explicit onboarding path: the adapter waits for `admit_run` to return, then
independently verifies the committed Run, quota reservation, and `run.queued`
event before recording onboarding completion. If that observation fails, the
Run remains committed; retry with the same admission idempotency key to replay
the Run and retry only the observation.

Member-removal composition must use `CompositeRemovalImpactProvider` with an
explicit required-domain set. Project ownership and grants are collected by
`ProjectRemovalImpactProvider`; all non-terminal Runs created by the member are
collected by `ExecutionRemovalImpactProvider`; open/checkpointed ChangeSets and
active, rebuild-pending, or quarantined Worktrees are collected by
`WorktreeRemovalImpactProvider`. Production composition must require all three
domains (`projects`, `runs`, and `worktrees`). A missing required domain fails
at startup; it is intentionally impossible to infer a zero impact from an
unwired provider.

Control-plane installation has five ordered PostgreSQL authority phases; do
not collapse them into one superuser migration connection:

1. A cluster principal operator runs
   `psql --no-psqlrc --file saas/control_plane/postgresql_principals.psql`.
   This idempotently creates and hardens every Alembic-named `NOLOGIN`
   capability principal and converges only the two fixed role-to-role
   memberships. It grants no schema or data privilege. The operator needs
   `CREATEROLE` plus `ADMIN OPTION` on any pre-existing named principal, but
   does not need application-table access.
2. The current database owner (or an explicitly audited superuser) runs
   `psql --no-psqlrc --file saas/control_plane/postgresql_database.psql`.
   This atomically revokes PostgreSQL's default `PUBLIC TEMPORARY` database
   privilege. Without that boundary, a service login could shadow an
   unqualified durable Outbox or Provider Journal relation in `pg_temp`.
3. The control-plane schema owner, which must be `NOSUPERUSER`, `NOCREATEDB`,
   `NOCREATEROLE`, `NOREPLICATION`, and `NOBYPASSRLS`, runs Alembic through the
   target revision. Migrations never create, alter, grant, or revoke role
   memberships; they fail before schema DDL when a required principal or fixed
   membership is absent or unsafe.
4. After the schema transaction commits, run
   `psql --no-psqlrc --file saas/control_plane/postgresql_roles.psql` as the
   control-plane database authority. This first-error-stopping transaction
   converges schema/table/function/RLS grants against the now-existing schema.
   Never invoke the `.sql` transaction bodies directly with plain `psql -f`.
5. A managed-cluster superuser then runs
   `psql --no-psqlrc --file saas/control_plane/postgresql_runner_agent_cluster.psql`
   exactly once after the roles projection and before runtime admission. The
   wrapper admits only PostgreSQL 18 with `max_notify_queue_pages=64` and
   `max_prepared_transactions=0`, both sourced from the configuration file
   with no pending restart, and with zero prepared transactions. It atomically
   removes unsafe `PUBLIC` catalog routine authority and restores only the
   exact audited central-role calls. Never run its `.sql` body directly, and
   never grant the managed-superuser credential to an application or Runner.

Give each service login exactly one role. Run identity/session endpoints with
`saas_authenticator`, governance workflows with `saas_governance`, runtime
resolution with `saas_app`, and dispatch workers with `saas_dispatcher`.
P3 admission/API transactions also use tenant-scoped `saas_app`; execution
workers inherit only `saas_executor`, while event delivery remains isolated in
`saas_dispatcher`. Secret redemption and Preview routing use the dedicated
`saas_secret_broker` and `saas_preview_gateway` roles. Both are `NOLOGIN`,
`NOSUPERUSER`, and `NOBYPASSRLS`; exact hashed-token RLS policies, rather than
caller-selected Tenant settings, reveal only the matching lease dependencies.

P4 is now `in_progress`. Its first implementation slice adds a durable weighted
fair queue, shared Runner Pool/registration records, compatibility-checked
Runner reconnect generations, persisted Run dispatches, monotonic lease/fence
state, and short-lived hashed capability tokens bound to Tenant, Space,
Project, Run, Runner incarnation, dispatch generation, action, and resource
scope. PostgreSQL claims use row locks plus a transaction-scoped advisory Pool
lock so concurrent replicas cannot oversubscribe capacity while
`saas_executor` remains read-only on Pool configuration. Five new tables use
`ENABLE + FORCE RLS`; real PostgreSQL tests prove two concurrent scheduler
replicas claim two distinct Tenants/Runs, counters remain consistent, ordinary
roles cannot enumerate Runner topology, and Tenant/Space scope cannot cross
dispatch or capability records. Exact-revision GitHub Actions run
`30901594129` verifies this slice at
`e0a806f66bd53ab60466d7294653fadf2d1b093d` with 642 tests on PostgreSQL 16
plus Chromium, migration head `p4a000000001`, 64 required wheel artifacts,
two patch replays, and source-intrusion enforcement. The first P4 gate is
therefore closed, but P4 cannot complete before the physical Worktree Adapter,
Sandbox/Secret/Egress/Preview, two real failure domains, network partition,
and N-1 rollback acceptance. The paired image-candidate run `30901594130`
proves repeated server and host archive builds have matching executable
manifest/config digests for both `linux/amd64` and `linux/arm64` at the exact
same revision. It remains explicitly non-production: the archives are not
registry-published immutable digests, keyless signatures and protected workflow
identity are unverified, vulnerability/license evidence is absent, and no
digest-pinned canary or N-1 rollback was exercised.

The second P4 implementation slice now persists credential-free Repository
bindings, atomic multi-Repository ChangeSet groups, immutable base revisions,
Project Worktree quotas, leased Worktree Instances, and append-only lifecycle
events. A partial unique index makes each modifying ChangeSet single-Writer;
readonly instances cannot become dirty. Every allocation consumes a live
scheduling capability and binds its hashed one-time token to Tenant, Space,
Project, Run fence, Runner connection generation, and Worktree lease
generation. The server generates the opaque runtime key and rejects path/URL
inputs; only the downstream Runner Adapter may map that key to a host path.
Dirty expiry with a checkpoint enters `rebuild_pending` and can be rebuilt on a
new Runner/fence from opaque recovery and environment references; dirty expiry
without recovery is quarantined. Release decrements transactional quota
counters, late writes fail after generation fencing, and physical deletion
requires an exact opaque-key/generation confirmation after the GC grace period.
Real PostgreSQL tests cover six-table forced RLS, scoped governance reads,
least-privilege service grants, and two concurrent control-plane instances
competing for one Writer. Exact-revision GitHub Actions run `30906291765`
verifies this slice at `bbec3f723e5ffdbe32a8734ed0d9ad00bb5a871a`
against official revision `45eab11d531f3224eb59b39da7d8cb18256e21a1`:
648 tests pass on PostgreSQL 16 plus Chromium, migration head
`p4b000000001` upgrades/checks/downgrades cleanly, the wheel contains 69
required SaaS artifacts, both downstream patches replay, and source intrusion
remains at 8 direct upstream files, 389 net added lines, and a 0.9885 isolated
code ratio. This closes only the Repository/ChangeSet/Worktree control-plane
subgate. A separate machine-readable gate remains pending for the physical Git
Runner Adapter, canonical-path/symlink/reparse-point and mount boundaries, and
real filesystem deletion; Sandbox, Secret, Egress, Preview, two-failure-domain,
and N-1 gates also remain pending.

The P4 physical Worktree subgate now includes an isolated POSIX Runner Adapter under
`saas/runner_adapter`, without changing the official Host Worktree helper. It
derives private checkout and state paths only from a server-generated opaque
key; resolves credential-free bindings through a Runner-local bare-mirror
registry; rejects executable Git configuration, embedded credentials, path
escape, symlink escape, device changes, nested mounts, and quota overflow; and
uses lease/run fences before materialization, checkpoint, and deletion. A
content-addressed recovery bundle can restore a checkpoint into a clean mirror
on another Runner. Materialize, checkpoint, and delete retries are idempotent
under the same exact fence, including recovery after partial local state loss.
Exact-revision GitHub Actions run `30910478415` verifies this implementation at
`85f4927bed35ddb2e5ddc85c3802a4bc99a29633` against official revision
`a47a9ee3bf7287f7e70fc0f599f241e43275ecfc`: 652 tests pass on PostgreSQL 16
plus Chromium, Pyrefly reports zero errors, migrations upgrade/check/downgrade,
the wheel contains 72 required artifacts, both patches replay, and source
intrusion remains within budget. The evidence successor wheel inventory now
requires 73 artifacts. Linux/POSIX filesystem enforcement in this adapter does
not prove Windows reparse-point handling, external object-store durability,
process Sandbox isolation during concurrent writes, or a two-failure-domain
recovery drill; those remain explicit release blockers.

The next P4 slice closes only the isolation/Secret/Preview control-plane
contract. Six new tables persist default-deny egress policies, server-selected
hard-sandbox profiles, vault-reference-only Secret bindings, one-time fenced
Run launch grants, one-time Secret access leases, and exact-host Preview
leases. All six use `ENABLE + FORCE RLS`; dedicated Secret Broker and Preview
Gateway roles can see a row and its Run/Runner/Worktree dependencies only with
the exact hashed lease token. Monotonic PostgreSQL guards reject grant/Secret
reactivation, Preview reactivation, and authority-binding mutation. The
downstream Runner adapter rejects client sandbox overrides, requires an outer
containment verifier, disables ambient environment and direct network access,
masks `.git`, binds the exact physical Worktree/fences, and uses the official
hard sandbox plus credential proxy. Parent-only credential source files stay
outside the Worktree in an atomically published `0700` directory as `0600`
files for the Prepared lifecycle because the official helper can transparently
restart. A POSIX advisory lock spans the complete lifecycle; startup cleanup
skips live peers, removes only a validated released lease, and fails closed on
malformed managed entries. They are never mounted into the sandbox. The
independent Preview application exchanges a body/Bearer capability for an
exact-host `__Host-` Cookie, rejects ambient SaaS credentials and Host/path
smuggling, bounds streamed bodies, strips forwarding/upstream Cookie headers,
and enforces control-plane CSP/COOP/CORP/referrer/frame headers.

Exact-revision GitHub Actions run `30918608868` verifies this contract at
`0bf50f61258be8966e36746d285f307a955a3201` against official revision
`a47a9ee3bf7287f7e70fc0f599f241e43275ecfc`: the PostgreSQL 16 + Chromium
matrix passes 662 tests, the separate official Linux bubblewrap and
credential-proxy acceptance passes 13 tests with 17 platform skips, Pyrefly
reports zero errors, migration head `p4c000000001` upgrades/checks/downgrades,
the wheel contains 78 required artifacts, both patches replay, and source
intrusion remains at 8 direct upstream files, 403 net added lines, and a 0.9901
isolated code ratio. Follow-up exact-revision runs `30920660193`, `30921247156`,
and `30922052283` verify crash cleanup, the expanded official malicious-egress
matrix, and the Linux cgroup-v2 verifier contract. The latest evidence
successor passes 678 PostgreSQL/Chromium compatibility tests, 36 official Linux
security tests with 22 platform skips, Pyrefly with zero errors, P4c migration
round trips, 81 wheel artifacts, two patch replays, and the 8-file/413-line
upstream intrusion budget. The cgroup verifier reads exact kernel facts and
fails closed; it does not create the production cgroup or prove a deployed
Runner Pod/container/microVM.

Exact-revision GitHub Actions run `30923776172` verifies the next P4 adapter
slice at `3b7505e32201898cd693b2c4548fe31517f04580`: 683 compatibility tests and
the 36/22 official Linux security matrix pass, Pyrefly reports zero errors,
P4c migrations round trip, the wheel contains 82 required artifacts, both
patches replay, and source intrusion remains at 8 files/413 lines with a 0.9903
isolated-code ratio. The adapter binds the full Preview Route Grant—including
Tenant, Space, Project, Run fence, Runner connection generation, Worktree lease
generation, and opaque Preview key—to one exact official `RunnerSession`
object. Replacing the official WebSocket session without advancing the SaaS
connection generation fails closed. A downstream Runner ASGI wrapper accepts
the internal route only from the official tunnel dispatcher, strips all
internal routing metadata before dispatch, rechecks the complete target
binding, and streams response chunks through the official frame protocol.
Request bodies remain bounded but buffered because official tunnel protocol v1
has one request-body frame. The process-local binding resolver is an explicit
composition seam, not multi-process placement proof. The evidence-successor
wheel inventory now requires 83 artifacts.

The next Runner-local slice adds `UnixSocketPreviewTarget`. It derives a short
socket name from the complete server-authorized route beneath an absolute,
private, Runner-owned root; no request or control-plane field can choose a TCP
host, port, or host path. The target accepts only the internal Preview tunnel
client, replaces the incoming Host with the fixed non-routable
`preview.invalid`, disables environment proxy discovery and redirects, and
uses only `httpx.AsyncHTTPTransport(uds=...)`. Activation requires a private
Runner-owned socket and pins device, inode, owner, and ctime; root or socket
replacement, symlinks, public modes, expiry, connection timeout, and stale
lifecycle state fail closed. Contract tests launch a real child Uvicorn process
on the derived UDS, stream an end-to-end response over the official Runner
frames, and verify header stripping, bounded timeout, and replacement denial.
Exact implementation run `30926375395` verifies this slice at
`0e689dd7ea89eb33b0341d5601d4f997bd57f227`: 688 compatibility tests and the
36/22 official Linux security matrix pass, Pyrefly reports zero errors, P4c
migrations round trip, the wheel contains 83 required artifacts, both patches
replay, and source intrusion remains 8 files/413 lines with a 0.9905 isolated
code ratio. The evidence-successor wheel inventory now requires 84 artifacts.

The Secret Broker transport slice now replaces Runner-side direct Vault
resolution with a dedicated end-to-end mTLS redemption channel. Both peers
must allow exactly TLS 1.3, validate the private CA, and require peer
certificates. The Broker derives the Runner UUID only from one exact
`spiffe://omnigent/runner/{uuid}` URI SAN; `runner_id` is intentionally absent
from the request body. The endpoint, Host, route, content framing, JSON member
set, body size, timeout, and response schema are fixed, environment proxy
discovery and redirects are disabled, and lease/fence/generation authorization
continues to execute in the existing PostgreSQL Secret Broker authority under
the server-injected Vault provider. Control-plane denials are collapsed at the
transport boundary so a caller cannot distinguish invalid from stale leases.

The Runner adapter now accepts separate launch-grant and Secret-redemption
authorities. Production composition can therefore keep launch grants on the
trusted control-plane client while injecting `MutualTlsSecretBrokerClient` for
plaintext redemption; the legacy combined in-process authority remains only a
backward-compatible test/composition seam. Every Secret lease also binds the
credential scheme, optional username, and exact environment-variable allowlist,
which the Runner rechecks before creating official credential-proxy entries.
The client retries a transport failure once with one UUIDv4 request ID. The
Broker shares the in-flight task and caches a successful response only in a
bounded, short-lived process-local replay table; request-ID reuse with another
Runner, Run, or lease token fails closed. End-to-end mTLS supplies request
integrity. Deployments must not terminate and recreate TLS between Runner and
Broker; doing so requires a protocol successor with independent request
proof-of-possession rather than treating a forwarding header as identity.

The 2026-08-05 upstream synchronization adds the official copy-on-write Runner
zygote/forkserver and semantic database query names. Local single-user Hosts
retain the upstream default. Managed Shared and Managed Dedicated execution use
`runner_adapter.process_policy` before constructing the official `HostProcess`:
the adapter requires the canonical `OMNIGENT_RUNNER_ZYGOTE=0`, rejects known
ambient provider/Git credential variables and arbitrary Runner passthrough, and
therefore selects the official direct-`Popen` path. This is a downstream
composition rule, not an upstream patch. Re-enabling the zygote in managed
modes requires independent proof that every fork resets cached credentials,
file descriptors, native-library state, telemetry, and Tenant/Space/Project/Run
context. CI now runs the new official zygote, harness client, query-context,
threadpool, allocator, cancellation, and process-lifecycle regressions while
the SaaS adapter keeps managed isolation fail closed.

Exact upstream-sync implementation run `30932712224` verifies this boundary at
`e76fe11e8bdc27cfa2013d1328924d4b0afce2eb`: 702 PostgreSQL/Chromium
compatibility tests, 56 new official zygote/query-context regressions, and the
36/22 official Linux security matrix pass; Pyrefly reports zero errors, P4c
migrations round trip, the wheel contains 86 required artifacts, both patches
replay against `8e17c9ec`, and source intrusion remains 8 files/432 lines with
a 0.9904 isolated-code ratio. The evidence-successor wheel inventory requires
88 artifacts. Eleven acceptance gates and the production decision remain
`NO-GO`.

The following Runner-local Preview slice adds
`RunnerPreviewProcessSupervisor` around the route-bound UDS target. One
supervisor instance is fixed to an exact Runner ID and connection generation;
it rejects grants for another incarnation. A server-owned immutable process
spec uses an absolute executable, a validated Runner-owned working directory,
an exact non-inherited and secret-free environment, and bounded startup,
health, request, and shutdown timeouts. Neither a Preview request nor route
metadata can select the command, environment, TCP endpoint, UDS path, or log
path. The process starts in a new session with closed file descriptors,
standard input disabled, and stdout/stderr directed to a private `0600` log.
The supervisor waits for the derived UDS, hardens it, pins its filesystem
identity, performs a direct UDS health probe, and only then publishes the exact
target binding. Stop, crash, and lease expiry revoke the binding before sending
signals to the owned process group; termination is bounded and escalates to
`SIGKILL`. Cleanup unlinks only the pinned socket identity and deliberately
leaves a replacement object for quarantine/investigation. Contract tests use
a real Uvicorn child and cover HTTP forwarding, ambient-secret exclusion,
health failure, startup timeout, TERM resistance, crash detection, route
expiry, Runner-generation mismatch, and pathname replacement. The wheel gate
now requires this adapter as its 89th SaaS artifact.

This closes only the local process-lifecycle contract subgate. It does not
prove a deployed service manager can reap children after the Runner itself
crashes, nor dedicated
Preview UID/mount/cgroup isolation, Placement reconciliation, deployed
Gateway-to-Runner mutual authentication, request-frame streaming, WebSocket,
custom-domain/certificate lifecycle, abuse controls, or two failure domains.
The aggregate P4 production gate and release decision therefore remain
pending and `NO-GO`.

Exact implementation run `30937413470` verifies the Supervisor contract at
`e5c90601d83a56f76899d61d1594bf3dcc539ed5` against official revision
`8e17c9ec081fc0219c71db773cc7bb0cb516633a`: 711 PostgreSQL/Chromium
compatibility tests, 56 official zygote/query-context regressions, and the
36/22 official Linux security matrix pass; Pyrefly reports zero errors, P4c
migrations upgrade/check/downgrade, the wheel contains 89 required artifacts,
both patches replay, and source intrusion remains 8 files/432 lines with a
0.9907 isolated-code ratio. The evidence-successor wheel inventory requires 90
artifacts. Eleven aggregate acceptance gates and the production decision remain
`NO-GO`.

The next P4 control-plane slice adds a durable Runner certificate lifecycle
authority without turning the SaaS database into a CA. External PKI remains
responsible for key generation, signing, chain validation, and private-key
custody. Migration `p4d000000001` stores only public leaf metadata: SHA-256
certificate and SPKI fingerprints, serial, exact canonical Runner SPIFFE URI,
purpose, Trust Bundle version, validity, Runner connection generation, and
rotation generation. An activation is serialized on the Runner registration,
is idempotent under concurrent retry, permits only one active certificate per
Runner and purpose, and moves older leaves into a bounded retiring overlap.
Revocation is immediate. PostgreSQL constraints, a partial unique index, and
append-only/monotonic triggers prevent time reversal, reactivation, authority
rebinding, and deletion. Activation and revocation produce non-secret Outbox
events; neither certificate DER nor a private key enters the database or event
payload.

Dedicated Secret Broker and Preview Gateway roles cannot enumerate this
table. Transaction-local, server-derived fingerprint and purpose settings
expose only one currently valid, non-revoked certificate; its Runner
registration becomes visible only when the stored connection generation still
matches the current Runner incarnation. `MutualTlsSecretBrokerServer` now
performs that durable certificate/generation authorization immediately after
the TLS handshake and before reading a redemption request or invoking Secret
Authority. A revoked,
expired, wrong-purpose, stale-generation, or unregistered leaf therefore
fails closed even when its CA chain is still cryptographically valid. Real
PostgreSQL tests cover forced RLS, concurrent activation, bounded overlap,
immediate revocation, Runner reconnect invalidation, role separation, and
database lifecycle guards. The wheel gate now requires the two authority
modules and P4d migration as artifacts 91 through 93.

Exact implementation run `30942353100` verifies this contract at
`54cdd1dceb952a0ec5ea88ed1bf572d41351f554`: 721 PostgreSQL/Chromium
compatibility tests, 56 official zygote/query-context regressions, and the
36/22 Linux security matrix pass; Pyrefly reports zero errors, P4d migrations
upgrade/check/downgrade, the wheel contains 93 required artifacts, both patches
replay, and source intrusion remains 8 files/432 lines with a 0.9910 isolated
code ratio. The certificate-lifecycle contract subgate is therefore passed;
the evidence-successor wheel inventory requires 94 artifacts.

This remains a certificate lifecycle contract, not deployed PKI evidence.
Production still requires an external issuer and Trust Bundle distribution
mechanism, automated issuance/renewal and emergency revocation, service
discovery, multi-replica/cross-host Broker and Preview composition, alerting,
and expiry / CA-compromise drills. Eleven aggregate acceptance gates remain
pending, so the aggregate P4 gate and release decision remain `NO-GO`.

The next P4 control-plane slice replaces process-local Runner tunnel ownership
with a durable Placement Router contract. Migration `p4e000000001` records one
live ownership lease per Runner, bound to the exact Connection Generation and a
monotonic Routing Generation. The gateway instance, hashed owner token,
server-generated opaque relay subject, bounded heartbeat deadline, and terminal
reason are control-plane authority; clients cannot select them. Claim,
heartbeat, drain, release, reconnect fencing, and bounded `SKIP LOCKED` expiry
reconciliation emit narrowly scoped, non-secret Outbox events. Append-only and
monotonic PostgreSQL triggers reject time reversal, authority rebinding, and
deletion.

Preview route reads use the dedicated Preview Gateway role and forced RLS. The
database reveals a Placement only when the transaction carries the exact
active Preview token hash, the Preview grant and Placement have not expired,
and both the grant and Placement still match the current Runner connection
generation. A receiving owner replica re-resolves these durable fields before
touching its local official `RunnerSession`; the official `TunnelRegistry` and
`RunnerSession` remain unchanged. Executor access is limited to Placement
mutation plus the four Placement Outbox event types and cannot insert unrelated
global events.

Exact implementation run `30948364396` verifies this contract at
`d8adb772f021135bf639ada20497b0e75325a62a`: 724 PostgreSQL/Chromium
compatibility tests, 56 official zygote/query-context regressions, and the
36/22 Linux security matrix pass; Pyrefly reports zero errors, P4e migrations
upgrade/check/downgrade, the wheel contains 97 required artifacts, both patches
replay, and source intrusion remains 8 files/432 lines with a 0.9913 isolated
code ratio. The Placement Router contract subgate is therefore passed; the
evidence-successor wheel inventory requires 98 artifacts.

The relay is still an authenticated transport interface rather than a deployed
cross-host mTLS or message-bus implementation. Therefore this slice removes the
process-local routing decision but does not establish production cross-host
delivery, failure-domain recovery, or the aggregate P4 gate. Eleven aggregate
acceptance gates remain pending and the release remains `NO-GO`.

The next downstream-only slice implements the `PreviewReplicaRelay` interface
as a one-request TLS 1.3 protocol without modifying official Omnigent code.
Both Gateway peers require certificates and exactly one Gateway SPIFFE URI SAN.
The sending replica verifies that the server certificate Gateway identity is
the same durable Placement owner selected by PostgreSQL, then calls an injected
certificate lifecycle authorizer before sending the request. The receiving
replica authorizes the client leaf before reading request bytes, requires the
wire destination to equal its own Gateway identity, and invokes
`accept_relay`, which re-resolves the exact Placement, Runner Connection
Generation, Routing Generation, relay subject, and Preview token before using
the local official Runner session.

The framed protocol rejects duplicate JSON members, ambiguous certificate
identities, caller-supplied endpoints, oversized metadata/bodies/chunks,
unsupported methods, invalid paths, ambient credential headers, and malformed
or stale route facts. Response chunks are streamed with an aggregate byte
limit, idle timeout, and client-disconnect cancellation. The client performs
no automatic transport retry, including for GET, because this initial contract
does not yet have a durable relay request/replay authority and must never
silently repeat an unknown-result mutation. Exact implementation run
`30951270461` verifies this transport at
`aac8f35407b15ad47b2ddc75b2bf9cc41ea126ce`: 734 PostgreSQL/Chromium
compatibility tests, 56 official zygote/query-context regressions, and the
36/22 Linux security matrix pass; Pyrefly reports zero errors, P4e migrations
round trip, the wheel contains 99 required artifacts, both patches replay, and
source intrusion remains 8 files/432 lines with a 0.9916 isolated-code ratio.
The mTLS Preview Relay transport subgate is therefore passed; the evidence
successor wheel inventory requires 100 artifacts. Production endpoint
discovery, external CA/Trust Bundle issuance and rotation, certificate
compromise drills, deployed cross-host topology, Preview WebSocket forwarding,
network-partition behavior, and two failure domains remain independent release
blockers.

The next downstream-only slice replaces the Relay's injected static discovery
and permissive lifecycle seam with PostgreSQL authority. Migration
`p4f000000001` adds an append-only Preview Gateway Instance registry and
purpose-separated Gateway certificate metadata. A process-lifetime Gateway ID
is globally unique and never reusable; its internal connect host, TLS server
name, failure domain, source revision, adapter contract, and registration-token
digest are immutable. Token-authenticated heartbeats may only extend a bounded
lease, draining stops new Runner ownership claims, and release or expiry makes
both discovery and certificate authorization fail closed. Existing p4e rows
are migrated to released, non-routable tombstones before a Placement-to-Gateway
foreign key is installed, so an upgrade never invents a trusted endpoint.

Relay client and server leaves now have distinct `preview_relay_client` and
`preview_relay_server` purposes with exact EKUs. Both require one Gateway
SPIFFE URI; a server leaf must cover only the registry-selected TLS server
name. The database stores fingerprints, SPKI digests, serials, validity,
Trust Bundle version, rotation generation, and lifecycle state, but never DER,
private keys, or raw registration tokens. Forced RLS reveals no token hash,
exposes only live non-secret endpoints to Executor/Preview roles, and exposes
only the exact presented fingerprint and purpose to the certificate
authorizer. Placement creation/renewal and Preview route reads now also require
a live Gateway lease. Rotation has bounded overlap, revocation is immediate,
and PostgreSQL triggers reject identity/endpoint rebinding, time reversal,
reactivation, deletion, and live Placement ownership by a stale Gateway.

Exact implementation run `30955223169` verifies this contract at
`ece5e58120e8a6147174736b89126abfee48e953`: 745 PostgreSQL/Chromium
compatibility tests, 56 official zygote/query-context regressions, and the
36/22 Linux security matrix pass; Pyrefly reports zero errors, p4f migrations
upgrade/check/downgrade, the wheel contains 103 required artifacts, both
patches replay, and source intrusion remains 8 files/432 lines with a 0.9920
isolated-code ratio. The persistent Gateway discovery/certificate subgate is
therefore passed; the evidence-successor wheel inventory requires 104
artifacts and eleven aggregate gates remain pending. This is still not
external CA issuance, production Trust Bundle distribution, deployed Gateway
registration/service discovery, cross-host failure evidence, or
two-failure-domain proof; the release remains `NO-GO`.

Migration `p4g000000001` adds two-phase Preview Gateway process activation.
New registrations are `starting` and cannot be discovered, selected for new
Runner ownership, or authorize Relay leaves as a live peer. The downstream
`PreviewGatewayRuntime` keeps the registration token in process memory, keeps
private keys inside an injected local/HSM provider, installs both
purpose-separated leaves, binds the listener, registers its actual port,
performs an exact advertised-endpoint mTLS readiness probe while the directory
is still non-routable, and activates only after both certificates and the
probe succeed. The process then heartbeats its bounded lease, rotates both
leaves as one coordinated pair, and drains existing local Tunnel ownership
before release.

The injected pre-activation probe contract requires an independently
authorized, server-owned platform health identity and pins the prepared server
leaf. Its implementation must not reuse
the Gateway's `preview_relay_client` leaf: ordinary Gateway certificate
authorization remains denied while the instance is `starting`. Both runtime
leaves must advertise the same accepted Trust Bundle version, and the
PostgreSQL activation trigger repeats that pair-consistency check.

Startup and maintenance failures are fail-closed: readiness is removed first,
all cleanup steps are attempted even if one fails, the listener is closed, the
durable identity is released with lease expiry as the database-outage fallback,
active leaves are revoked, and provider-held private material is discarded.
The PostgreSQL trigger independently requires both valid certificate purposes
for `starting -> active`, preserves activation time, and rejects terminal time
reversal. The Preview Gateway role can heartbeat, drain, or release only its
token-selected row and has no grant to write `activated_at`; final activation
uses the platform authority transaction. Local real-PostgreSQL migration and
negative-RLS checks pass. Exact implementation run `30959947571` verifies the
contract at `e698027952e171bf3a22e4360373965626f56fd7`: 753
PostgreSQL/Chromium compatibility tests, 56 official zygote/query-context
regressions, and the 36/22 Linux security matrix pass; Pyrefly reports zero
errors, p4g migrations upgrade/check/downgrade, the wheel contains 106 required
artifacts, both patches replay, and source intrusion remains 8 files/432 lines
with a 0.9923 isolated-code ratio. The runtime lifecycle subgate is passed; the
evidence-successor wheel inventory requires 107 artifacts and eleven aggregate
gates remain pending.
External CA/HSM deployment, Trust Bundle rollout, DNS/load-balancer health,
cross-host failure and partition behavior, and two failure domains remain
production blockers, so this candidate does not change the `NO-GO` decision.

The next downstream-only p4h candidate turns the lifecycle coordinator into a
packaged `omnigent-saas-preview-gateway` process without adding another official
source patch. Its closed, non-secret JSON schema rejects unsafe ownership/modes,
symlinks, unknown or duplicate fields, static identities/tokens, non-loopback health
binds, booleans masquerading as ports, non-finite durations, and unsafe heartbeat or
rotation timing. Each process start creates a new Gateway ID and high-entropy
registration token in memory. Only a trusted deployment-time `module:attribute`
factory may inject the exact narrow directory/certificate clients, key provider,
Relay listener, independent mTLS health probe, and persistent drain observer; the
process contract explicitly excludes a `saas_platform` PostgreSQL credential.

The executable starts a detail-free loopback `/livez` and `/readyz` server before the
runtime, bounds HTTP headers, and makes readiness depend on the durable active state,
fatal-error state, real TLS 1.3 advertised-endpoint handshake, hostname validation,
and exact server-leaf pin. SIGTERM/SIGINT can interrupt blocked startup and still
close the listener, release/expire the process identity, revoke leaves, and discard
key material. The wheel packages hardened systemd and Kubernetes templates with a
dynamic/non-root identity, read-only filesystem, no capabilities, seccomp, topology
constraint, exec health probes, and default-deny networking. The Kubernetes example
is deliberately one replica because its endpoint is static; scaling is invalid until
each Pod receives a server-selected directly routable endpoint and matching name.

Exact implementation run `30964370004` verifies the p4h contract at
`742eafd22e82244df89efe7ffc965eb3d5e0bcc0`: 775 PostgreSQL/Chromium
compatibility tests, 56 official zygote/query-context regressions, and the 36/22
Linux security matrix pass; Pyrefly reports zero errors, p4g migrations round trip,
the wheel contains 113 required SaaS artifacts, both patches replay, and source
intrusion remains 8 files/434 lines with a 0.9925 isolated-code ratio. The p4h
process/deployment contract subgate is therefore passed; the evidence-successor wheel
inventory requires 114 artifacts and eleven aggregate gates remain pending. The
templates are not deployment evidence: external CA/HSM and Trust Bundle operations,
signed immutable image promotion, control-plane mTLS policy, DNS/LB registration,
NetworkPolicy allowlists, cross-host partitions, two failure domains, and N-1
rollback remain production blockers. The release stays `NO-GO`.

The next downstream-only p4i candidate replaces the Gateway deployment factory's
abstract privileged client with a real, bounded TLS 1.3 control transport. A dedicated
control leaf must contain exactly
`spiffe://omnigent/preview-gateway-control/{process-generated-gateway-id}` and only
ClientAuth/digital-signature workload semantics. The server binds that identity to
every fixed action before reading the JSON body; Relay leaves and the independent
platform-health identity are rejected. Requests cannot select authority timestamps,
cannot redirect or use environment proxies, and cannot revoke a certificate owned by
another Gateway. Only the control-plane service receives PostgreSQL roles: local real
TLS plus PostgreSQL 16 tests traverse separate `saas_platform` and
`saas_preview_gateway` session factories through registration, purpose-separated
certificate activation, durable activation, heartbeat, drain, scoped revocation, and
release. The process still receives no database credential.

Exact implementation run `30967154951` verifies the p4i contract at
`0516d80ca3dc5a1b1a6e8108bf92fc673074be82`: 781 PostgreSQL/Chromium
compatibility tests, 56 official zygote/query-context regressions, and the 36/22
Linux security matrix pass; Pyrefly reports zero errors, p4g migrations round trip,
the wheel contains 115 required SaaS artifacts, both patches replay, and source
intrusion remains 8 files/434 lines with a 0.9928 isolated-code ratio. The p4i
control-plane transport subgate is therefore passed; the evidence-successor wheel
inventory requires 116 artifacts and eleven aggregate gates remain pending. External
workload issuance, CA/HSM and Trust Bundle operations, signed immutable deployment,
unique per-Pod endpoints, NetworkPolicy allowlists, cross-host partitions, two
failure domains, and N-1 rollback are not implied; the release remains `NO-GO`.

The first P5 slice adds migration `p5a000000001` and a durable signed outbound
Webhook authority. Endpoint rows contain only canonical HTTPS metadata, event types,
Secret references, and rotation versions. Delivery rows retain immutable payload/hash
facts and stable Delivery/Event IDs across retries and authorized DLQ replay. Multiple
replicas claim bounded leases with `FOR UPDATE SKIP LOCKED`; network I/O occurs after
the database lock is released. Versioned HMAC-SHA256 signatures support a bounded
old/new overlap, while Secret-provider and replay-authorization calls occur outside
row locks.

Every attempt re-resolves the complete A/AAAA set and rejects the target if any answer
is not globally routable, including IPv4-mapped IPv6, NAT64 well-known/local, Teredo,
and 6to4 transition forms. The sender pins one validated public address, but keeps the
original hostname for Host, SNI, and certificate verification; redirects, environment
proxies, and non-POST methods are disabled. Both Webhook tables use forced RLS. The
dedicated `saas_webhook_dispatcher` can read endpoints, read/update deliveries, and
insert only allowed Outbox audit facts, but cannot modify endpoint configuration.
Triggers reject delivery fact rewrites, lifecycle reversal, and unauthorized replay.

Implementation/stabilization run `30980110086` passes 795 PostgreSQL/Chromium tests,
56 official regressions, and the 36/22 Linux security matrix at `d8f47804`; evidence
successor run `30980779159` repeats the complete gate at `d9a9528c`, including Pyrefly
zero errors, p5a migration round trip, 121 required wheel artifacts, both patches, 11
pending aggregate gates, and the 8-file/434-line/0.9931 intrusion result. Image run
`30978680569` repeats Server/Host builds on both supported architectures, but its OCI
archives are not published, signed, vulnerability-cleared, canaried, or rolled back.
Production DNS/egress enforcement, external Secret/KMS operation, receiver
conformance, capacity/SLO, deletion, PITR, isolated restore, multi-AZ, and signed image
promotion remain pending; P5 is `in_progress` and the release remains `NO-GO`.

The next P5 recovery slice adds a strict machine-readable policy and evidence
validator without manufacturing operational proof. A qualifying record must bind the
exact upstream, adapter, schema, and downstream product revisions; measure T0-T2
RPO/RTO; prove an encrypted deletion-protected backup outside the source failure
domains; restore with traffic disabled into separately hashed account, network, KMS,
object-prefix, search-index, and Runner-pool boundaries; pass the complete 50-table
control-plane and 18-table runtime forced-RLS, cross-tenant, tombstone, revocation,
binding, ledger, object, key, and canary matrix; and reference a signed immutable
artifact with independent SRE, security, and data-owner attestations. Both a current
Tenant drill and a current cluster drill are required. The repository intentionally
contains neither, so the structural check passes while production readiness remains
blocked. CI fixtures, backup-job success, screenshots, and local restores cannot close
the gate.

Exact implementation run `30983318630` verifies this fail-closed contract at
`689d364ca809d762cfe1d21232c5f50739cc9be2`: 801 PostgreSQL/Chromium
compatibility tests, 56 official regressions, and the 36/22 Linux security matrix
pass; Pyrefly reports zero errors, p5a migrations round trip, the wheel contains 124
required artifacts, both patches replay, and source intrusion remains 8 files/437
lines with a 0.9931 isolated-code ratio. The recovery evidence verifier subgate is
therefore passed, while the actual multi-AZ/PITR/isolated-recovery gate remains
pending with zero qualifying records and two missing scopes.

A separate disposable PostgreSQL 16 contract now creates a source database, applies
the exact official and SaaS migration heads plus both forced-RLS layers, seeds two
Tenant/workspace scopes, creates a custom-format logical backup, and restores it into
a separately generated database. It then replays post-backup identity/session
revocation, membership removal, and Tenant deletion-marker facts; reapplies
least-privilege roles; verifies the canonical 50-table control-plane and 18-table
runtime RLS inventories; runs cross-Tenant and cross-workspace negative probes; and
compares canonical hashes and row counts across eleven selected tables before dropping
both databases. Client credentials stay in the subprocess environment rather than
arguments. The report is explicitly `ci_contract_not_production_drill`: it proves
logical restore compatibility only, not WAL/PITR, multi-AZ, another failure domain,
external KMS/object lock/signing, or production RPO/RTO.

Exact Linux/PostgreSQL 16 run `30986200469` verifies the implementation at
`470105a68a9992ba12258c3be96b600ca4e0ae28`: 809 PostgreSQL/Chromium
compatibility tests, 56 official regressions, and the 36/22 Linux security matrix
pass; the 2.961-second restore contract reports matching selected-table hashes,
50/17 forced-RLS inventories, both cross-scope negative probes, and complete
post-backup revocation/deletion-marker replay. Pyrefly reports zero errors, p5a
migrations round trip, the wheel contains 128 required artifacts, both patches
replay, and source intrusion remains 8 files/443 lines with a 0.9931 isolated-code
ratio. This closes only the isolated logical-restore contract subgate; production
recovery evidence remains absent and the aggregate gate remains pending.

Tenant deletion now has a separate fail-closed manifest contract. Its policy requires
one exact-revision production record to cover thirteen authoritative surfaces:
control-plane and Runtime databases, objects/artifacts, vector/search, caches,
queues/DLQs, Provider/Connector state, Runner Worktree/recovery material, Webhooks,
Secret/KMS state, logs/traces, immutable audit/ledger facts, and backups/snapshots.
Primary surfaces must reach zero or cryptographic erasure. Retained logs and ledgers
must remove direct identifiers and carry bounded retention; backups must be
runtime-inaccessible, bound to a deletion tombstone, and have a bounded purge date.
The canonical manifest, immutable artifact/DSSE envelope, exact revisions, cross-scope
checks, restore tombstone check, and independent privacy/security/data-owner
attestations are mandatory. The repository intentionally has zero production deletion
records, so structural validation passes while production readiness is blocked. A CI
fixture, successful worker, database row count, or screenshot cannot close this gate.

Exact Linux/PostgreSQL 16 run `30988807799` verifies the deletion-contract
implementation at `cd681559684377a5d5b0a25c23c23749eeb85d48`: 817
PostgreSQL/Chromium compatibility tests, 56 official regressions, and the 36/22 Linux
security matrix pass; Pyrefly reports zero errors, p5a migrations round trip, the wheel
contains 133 required artifacts, both patches replay, and source intrusion remains 8
files/446 lines with a 0.9932 isolated-code ratio. Its report contains thirteen required
surfaces but zero production records, zero qualified records, and one explicit blocker.
This closes only the verifier-contract subgate; no production Tenant deletion, purge,
capacity/SLO, or aggregate P5 gate is proven.

Production SLO and capacity proof now has its own fail-closed manifest contract. It
binds the exact production baseline's six SLOs and seven-service catalog to a complete
30-day production observation across two failure domains, error-budget and 1-hour/
6-hour burn-rate limits, secret-free active dashboards, five capacity scenarios for
every service, ten resource dimensions, six routed alert drills, exact release and
schema revisions, immutable artifact/DSSE references, and independent SRE,
product-owner, and service-owner attestations. Capacity testing must run in an isolated
production-like environment with production traffic disabled, retain at least 20%
headroom, stay below 80% saturation, and preserve 0.90 Tenant fairness. CI timings,
health endpoints, synthetic fixtures, and a single replica cannot qualify.

The repository intentionally keeps all six dashboards `planned` and contains zero
production observation records. Therefore
`python -m saas.scripts.check_slo_capacity_readiness` reports structural `pass` but
production `blocked` with seven explicit blockers. This closes only the verifier-
contract subgate after exact CI acceptance; it does not manufacture capacity, SLO,
multi-AZ, or aggregate P5 proof.

Exact Linux/PostgreSQL 16 run `30991532016` verifies the SLO/capacity-contract
implementation at `05fbe7d80d32e5337f515a389520c1813d2a469f`: 827
PostgreSQL/Chromium compatibility tests, 56 official regressions, and the 36/22 Linux
security matrix pass; the disposable logical restore passes in 2.82 seconds, Pyrefly
reports zero errors, p5a migrations round trip, the wheel contains 138 required
artifacts, both patches replay, and source intrusion remains 8 files/449 lines with a
0.9933 isolated-code ratio. The report confirms seven services, six SLOs, five
scenarios, zero production records, zero qualified records, and seven readiness
blockers. This closes only the fail-closed verifier-contract subgate; the actual
production SLO/capacity and aggregate gates remain pending.

The strict image-supply-chain v2 contract now rejects policy weakening as well as
malformed evidence. Approved image names/targets, smoke probes, labels, dependency
locks, official regressions, repository paths, workflow/OIDC identity, dual SBOM,
provenance, signature subject, and transparency metadata are exact. Vulnerability
and license admission must bind the candidate digest, contain no Critical/High,
denied, unknown, or inline exception result, and complete before canary. Only an
immutable allowlisted-registry digest with a receipt may enter a one-hour SLO/security
canary; a distinct signed/provenanced N-1 digest must then recover within 900 seconds
before three independent approvals. Absolute, escaping, symlinked, malformed, stale,
different-release, reordered, or boolean-for-integer evidence fails closed.

Exact Linux/PostgreSQL 16 run `30994862629` verifies this contract at
`0200b00a116bffbf3c722d82fe05c3735f69014a`: 836 compatibility tests, 56 official
regressions, the 36/22 Linux safety matrix, a 2.784-second disposable logical restore,
Pyrefly with zero errors, migration round trip, the 139-artifact wheel, both patch
replays, and the 8-file/449-line intrusion result with a 0.9935 isolated-code ratio.
Its supply-chain report intentionally contains two policy images but zero evidenced or
promoted images and one blocker. This closes only
`p5-image-supply-chain-evidence-verifier-contract`; no registry publication,
signature, protected-environment execution, canary, N-1 rollback, human approval,
P0 production-image gate, or aggregate P5 gate is proven. The evidence-successor wheel
requires 140 artifacts and the release stays `NO-GO`.

Exact implementation run `30929785430` verifies this transport at
`d6ec4b51cddd3583cc9a583476adb0163d760b51`: 693 PostgreSQL/Chromium
compatibility tests and the 36/22 official Linux security matrix pass, Pyrefly
reports zero errors, P4c migrations round trip, the wheel contains 85 required
artifacts, both patches replay, and source intrusion remains 8 files/413 lines
with a 0.9907 isolated-code ratio. The evidence-successor wheel inventory now
requires 86 artifacts. The PostgreSQL Secret Broker role tests run in the same
CI, but they are independent of the TLS socket test and therefore do not prove
a deployed cross-host mTLS-to-PostgreSQL path.

The production gate therefore remains pending: no real Runner deployment has
yet passed the cgroup verifier; the Secret Broker mTLS adapter has no deployed
certificate issuance, rotation/revocation, service discovery, replica retry,
Vault/KMS, memory-lifetime, or separate-host evidence; the Preview tunnel does
not yet have deployed mutually authenticated cross-process/host transport;
Preview WebSocket, custom-domain, and abuse controls remain incomplete; the
local Supervisor has no deployed external service-manager recovery evidence for
Runner death or dedicated UID/mount/cgroup isolation; and two real failure
domains, network partition, and N-1 rollback are unproven.

After official migrations and Runtime RLS installation, run
`saas/runtime_rls/postgresql_roles.sql` and grant each runtime service login
only `omnigent_runtime_app`. The service login must not own protected tables
and must remain `NOSUPERUSER NOBYPASSRLS`.

This remains a validated implementation slice, not complete production SaaS
proof. P2's current implementation gate passes the local and GitHub PostgreSQL
16 matrices for control-plane/Runtime RLS, concurrent Identity/Outbox/Owner
operations, Binding Saga fault injection, patch replay, and real Chromium
Project Admin tests. OIDC callback verification has an immutable passing CI
record; P0 remains in progress because approved production ADRs, reproducible
signed images, and Service Catalog/SLO/RPO/RTO evidence are pending. The P1
Context Shell/multi-replica/degradation gate now has an immutable passing
PostgreSQL 16 + Chromium CI record, so P1 is complete.

P3 is complete. Its durable execution authority is verified at exact
implementation revision `1e574b4c3b0e341d933a61c7fd521908d9dd2540` by
GitHub Actions run `30895599094` (625 tests on PostgreSQL 16 plus Chromium,
Alembic upgrade/check/downgrade, Pyrefly, 57 required wheel artifacts, patch
replay, production baseline checks, and source-intrusion enforcement):

- Task stores durable intent but no duplicated status; Task state is derived
  from authoritative Runs. Session has an independent active/closed lifetime,
  and the append-only Session-Task link prevents either lifecycle from owning
  the other;
- admission locks a versioned project quota and atomically creates the Run,
  quota reservation, `run.created`/`run.queued` events, and matching Outbox
  push intents. Tenant-scoped idempotency rejects payload changes;
- the queue is the `saas_runs` table. PostgreSQL workers claim with
  `FOR UPDATE SKIP LOCKED`; every lease carries an opaque token plus monotonic
  fence, and every heartbeat/transition rejects stale or expired workers;
- cancellation, expiry recovery, bounded requeue/orphaning, and replay operate
  only on persisted state. Each Run event increments a per-Run sequence while
  its Outbox intent is inserted in the same transaction, so a push cannot
  precede persistence;
- model, tool, and external effects reserve an idempotency key before I/O.
  Unknown results remain explicit; unsafe retry requires an approval or
  compensation reference. Artifacts are content-addressed, revision-labelled,
  and PostgreSQL triggers reject updates and deletes, including platform-role
  attempts;
- all ten P3 tables have tenant/space scope plus `ENABLE` and `FORCE RLS`.
  Real PostgreSQL tests prove missing-context and cross-tenant denial,
  non-bypass executor access, immutable artifacts, and one-winner concurrent
  quota admission.

P4 multi-failure-domain execution and Worktree isolation remain partially
implemented. P5 has passed Webhook/SSRF, recovery-verifier, isolated-restore,
tenant-deletion-verifier, SLO/capacity-verifier, and image-supply-chain-verifier
contract subgates; real production recovery, capacity/SLO, deletion, and signed
image evidence remains pending. P6 is now in progress through machine-identity,
enterprise group/custom-role, and enterprise access-lifecycle code-contract slices;
billing, enterprise federation, audit export, privacy, the complete API platform,
and commercial acceptance remain pending. None
may be inferred from a code-contract or CI-only subgate.

The first P6 slice adds the downstream-only migration `p6a000000001`, explicit
Service Accounts, and hashed API Keys. Service Accounts are non-interactive and
project-bound; an explicitly selected active Steward is independent from `created_by`,
so no creator membership or content permission is inherited. Key issuance requires
the manager to hold both `grant.manage` and every delegated permission. The one-time
`omk_` token is HMAC-digested with an injected pepper and binds exact permissions,
canonical network CIDRs, expiry, Project scope, and account security version.

The optional public router is registered at `/api/v1` while internal compatibility
routes remain under `/saas`. Cookie management calls retain Origin/CSRF protection;
machine Bearer tokens are accepted only by `/api/v1`, and Cookie plus Bearer is
rejected as `ambiguous_authentication`. Rotation, revoke, Steward transfer, and
suspension are transactional and secret-free in Outbox. Revocation is checked on
every request while `last_used_at` writes are coalesced. The
`ServiceAccountRemovalImpactProvider` blocks member removal until explicit Steward
transfer. PostgreSQL uses 52 control-plane forced-RLS tables and an exact
`app.api_credential_id` lookup for the authenticator role; backup/restore and tenant
deletion policies include machine-credential revocation. See
`saas/production/runbooks/api-credentials.md` for deployment and incident gates.

The reviewed official baseline has advanced through two current P6-era syncs. The
first zero-conflict sync to `d794ef4f9f641f5b1f07dd586fae9ecac505a733` spans
eleven commits and 27 changed files and is verified by exact run `31011047850`.
The second strictly later sync to `8c191ac06b55cde1ce2f299170595975bdd5cd52`
spans two commits and five files with zero conflicts. Its first run `31018890417`
failed closed because the Runtime and production-policy Revision Contracts still
named `d794ef4f`; those contracts were advanced atomically before rerun.

Exact second-sync run `31019511803` at
`6121663028d8d5501b1a41f284146ec8ce3b4e40` passes 856 compatibility tests,
57 official Zygote/query-context regressions, the 36/22 Linux safety matrix,
Pyrefly with zero errors, the `p6a000000003` round trip, both patch replays, and
the 155-artifact implementation wheel. PostgreSQL 16 logical restore completes in
2.923 seconds with 56/17 forced-RLS inventories. The two-consecutive-sync condition
is now satisfied, but pricing, billing reconciliation, customer acceptance, and the
other production evidence remain missing; the combined commercial gate and release
decision therefore remain `NO-GO`. The evidence-successor wheel requires 156
artifacts.

The second P6 slice adds Tenant-owned groups and project-scoped custom roles in
downstream migration `p6a000000002`. Group membership grants nothing by itself;
authorization is added only by a live group-to-role assignment. Custom roles compile
only canonical Project permissions, reject Critical and delegation-management
permissions, and require the manager to hold `grant.manage`, `custom_role.manage`,
and every delegated permission. Membership and assignment expiry fail closed, and
authorization explanations expose the exact role ID and version.

The enterprise Admin API stays on the existing `/saas` Cookie surface with Origin and
CSRF enforcement, action-level permission registration, opaque UUID keyset cursors,
and database-bounded pages. Mutations use Tenant-scoped idempotency and secret-free
Outbox facts. Direct group-member removal revokes sessions, increments the user's
security version, and increments every affected Project authorization version;
Tenant member-removal preflight includes group and role-assignment impact, rejects a
stale snapshot, and revokes group access in the same transaction. Space-only removal
does not silently erase Tenant-wide group membership.

The four new tables bring the canonical control-plane inventory to 56 forced-RLS
tables. Exact run `31008792059` at
`85e4399de928bc7cffb76dbe763f9a2e3b1641a6` passes 852 compatibility tests,
57 official Zygote/query-context regressions, the 36/22 Linux safety matrix, Pyrefly
with zero errors, the `p6a000000002` migration round trip, both patch replays, and the
150-artifact implementation wheel. PostgreSQL 16 restore completes in 2.954 seconds
with 56/17 forced-RLS inventories and two restored rows in each enterprise table;
cross-Tenant reads/writes, missing context, stale authorization, and concurrent
member-removal losers fail closed. The intrusion result remains 8 direct upstream
files, 449 net added LOC, two patches, and a 0.9941 isolated-code ratio. This closes
only `p6-enterprise-group-project-custom-role-contract`; directory sync, group
archive/role retirement/bulk lifecycle, federation/SCIM, complete audit/API/console/
privacy, billing, production evidence, eleven aggregate gates, and release `NO-GO`
remain open. The evidence-successor wheel requires 151 artifacts.

The third P6 contract slice adds explicit Group Archive, Project custom-role
retirement, and bounded atomic group-membership batches in downstream migration
`p6a000000003`. The Cookie-only Admin API exposes these as POST state transitions
with trusted Origin/CSRF checks, action-level authorization, expected versions,
reasons, and Tenant-scoped idempotency. Archive removes all active memberships,
revokes active role assignments, invalidates affected users and sessions, and bumps
affected Project authorization versions; retirement revokes assignments and bumps
its Project version. Batch operations accept 1--100 unique users, prevalidate every
item, and roll back the whole batch on one invalid target.

Every enterprise write takes a Tenant-scoped PostgreSQL transaction advisory lock,
so cross-group and cross-role Admin operations serialize without cross-resource
deadlocks while other Tenants remain independent. Legacy archived/retired rows gain
an explicit backfill marker instead of invented operator provenance; PostgreSQL
temporarily relaxes FORCE RLS only for the migration owner inside the migration
transaction and restores it before commit. The restore drill replays post-backup
Archive and Retire transitions and verifies terminal actor, time, reason, membership,
assignment, and RLS state.

Exact run `31016011969` at
`7578d2d1bcbfae260142bad166a1851ce4168dfa` passes all 856 compatibility tests,
57 official Zygote/query-context regressions, the 36/22 Linux safety matrix,
Pyrefly with zero errors, the `p6a000000003` round trip, both patch replays, and the
153-artifact implementation wheel. PostgreSQL 16 restore completes in 3.086 seconds
with 56/17 forced-RLS inventories and post-backup enterprise-lifecycle replay. The
intrusion result remains 8 direct upstream files, 449 net added LOC, two patches,
and a 0.9942 isolated-code ratio. This closes only
`p6-enterprise-access-lifecycle-contract`. Dedicated pre-execution impact snapshot
and approval UI, directory sync/SCIM/federation, billing, complete audit/API/console/
privacy capability, production evidence, eleven aggregate gates, and release
`NO-GO` remain open. With the two immutable evidence records, the evidence-successor
wheel requires 155 artifacts.

The fourth P6 contract slice adds the dedicated downstream migration
`p6a000000004` and a fifth enterprise table for Group Archive and custom-role
Retire impact/approval records. Cookie Admin callers must create a 15-minute,
SHA-256-bound server snapshot, obtain a decision from a different currently
authorized principal, and execute with the same target version, reason, requester,
fresh authentication and approved preflight ID. Approval and execution re-collect
the exact affected memberships, assignments, user/session versions and Project
authorization versions; drift, expiry, self-approval, approver permission loss,
cross-scope reuse and concurrent losing decisions fail closed. Only the impact
summary enters API responses and secret-free Outbox events.

The canonical control-plane inventory is now 57 forced-RLS tables. The isolated
PostgreSQL 16 logical-restore contract preserves two preflight rows and replays an
approved record to `executed` after the backup point, while its tenant-scoped
negative probe prevents another Tenant from observing the record. Exact run
`31025362985` at `7f3350ffad677e7249ef5eda6ad4fb738e617503` passes 859
compatibility tests, 57 official regressions, the 36/22 Linux security matrix,
Pyrefly with zero errors, the migration round trip, both patch replays, and the
157-artifact implementation wheel. Restore completes in 2.948 seconds and the
8-file/449-line/two-patch/0.9944 intrusion result remains within budget. This closes
only `p6-enterprise-access-impact-approval-contract`; the evidence-successor wheel
requires 158 artifacts.

These remain code and CI contracts: the productized approval inbox/confirmation UI,
directory sync/SCIM/federation, high-cardinality production performance, billing,
complete audit/API/console/privacy capability, production evidence, eleven aggregate
gates, and release `NO-GO` remain open.

The fifth P6 contract slice advances the downstream head to `p6a000000005` and
productizes that approval boundary inside the existing `/saas/admin/projects`
control plane rather than introducing a second Admin application. Three bounded GET
surfaces expose only the current actor's requests, a Tenant Group decision inbox, and
the selected visible Project's custom-role decision inbox. Requesters are excluded
from their own decision queues, expired requests are omitted, full impact snapshots
remain server-only, and dedicated requester/scope indexes keep pagination bounded.
The UI renders server-derived impact counts and requires a reason-bearing confirmation
for prepare, approve, reject, and execute. A real Chromium test signs in two different
administrators and proves approve, reject, requester-only execution, archived/retired
terminal state, and absence of browser console errors.

This does not turn the official server-wide `/settings/members` account page into
Tenant administration. `/saas/admin` currently manages Project memberships plus
enterprise Group/custom-role approval; a unified Tenant Members module for invitation,
Tenant/Space role changes, suspension/removal, identity connections, Owner transfer,
and removal impact preflight remains part of the broader pending enterprise console
gate. The official user workspace and SaaS Admin modules continue to share one product
and authentication plane, with server authorization—not a separate deployment—deciding
which management surfaces and actions are available.

Exact run `31030826038` at
`67d53a11c54f1fa0715f000f3f18a13b12366d12` passes all 861 PostgreSQL/Chromium
compatibility tests, 57 official regressions, the 36/22 Linux security matrix,
Pyrefly with zero errors, the `p6a000000005` migration round trip, both patch
replays, and the 159-artifact implementation wheel. Its PostgreSQL 16 logical
restore completes in 2.916 seconds with 57/17 forced-RLS inventories, two
preflight rows, cross-Tenant denial, and post-backup approval replay. The
8-file/449-line/two-patch/0.9945 intrusion result remains within budget. This is
evidence for the still-pending
`p6-enterprise-identity-audit-api-platform-console-privacy` aggregate gate; it
did not close that gate or, at that revision, complete Tenant Members management.
The eleven pending aggregate gates and release `NO-GO` were unchanged. The
evidence-successor wheel requires 160 artifacts.

The first evidence-successor run then failed closed on a real browser ordering race:
an initial empty Group response could arrive after the post-create refresh and erase
the newer render. The console now assigns monotonically increasing read revisions to
Group, custom-role, and approval lists; logout invalidates every in-flight revision,
and role/approval responses must still match the captured actor, Tenant, Space, and
selected Project. The Chromium test deterministically delays a previously completed
empty GET until after create and proves that the stale response is discarded.

Exact corrective run `31032344986` at
`1382f2032c9f804e3ce702af03b0c3953e13fe9d` passes 861 compatibility tests,
the 57 official regressions, the 36/22 Linux matrix, Pyrefly, migration round trip,
both patches, the 160-artifact wheel, and the unchanged 8-file/449-line/0.9945
intrusion result. The evidence-successor wheel now requires 161 artifacts. Eleven
aggregate gates and release `NO-GO` remain unchanged; at that revision complete
Tenant Members management was still open.

The sixth P6 contract slice now exposes `Tenant Members` in the existing
`/saas/admin/projects` control plane. It is not a second backend or a repurposed
official `/settings/members` page. Authorized administrators can search and filter
Tenant members, inspect privacy-bounded login-method summaries and every Space
membership, change Tenant/Space roles, suspend or resume access, create/list/reissue/
revoke/accept invitations, transfer Owner, and execute removal only after a fresh
server impact preflight. Role and status changes use CAS versions and revoke affected
sessions; high-risk Admin elevation additionally requires current-Owner authority,
fresh authentication, and a reason. Invitation tokens are one-time, `no-store`,
hash-bound under exact-token PostgreSQL RLS, and absent from Outbox.

The HTTP integration fails closed unless the member-directory and membership-
lifecycle services are configured together. `saas_authenticator` handles login and
invitation acceptance while `saas_governance` handles explicit membership changes;
neither gets the other's broad table authority. All Cookie writes bind actor,
Tenant, and Space and enforce Origin/CSRF, action permission, reason, expected
version, and Tenant-scoped idempotency.

Runs `31041546256` and `31041546082` first failed on a real Chromium ordering race:
the Space Role action could overtake the preceding Tenant Role refresh. The fix at
`17e3f6b4` serializes all selected-member governance actions until the server write
and list reload complete, and tests wait for server-confirmed version advancement.
Exact run `31042515162` then passes 865 compatibility tests in 154.34 seconds, a
3.498-second PostgreSQL 16 restore with 57/17 forced-RLS inventories, 57 official
tests in 39.48 seconds, the 36/22 Linux matrix in 17.19 seconds, Pyrefly, the
`p6a000000007` migration round trip, both patches, the 166-artifact wheel, and the
8-file/449-line/0.9947 intrusion result. The evidence-successor wheel requires 167
artifacts.

This closes the Tenant Members product slice but not SCIM/directory sync, enterprise
federation, bulk/delegated lifecycle, billing, full audit/API/privacy, production
topology or recovery, the pending P6 enterprise aggregate, any of the eleven
aggregate gates, or release `NO-GO`.

Evidence successor `04bb33a1` is revalidated by compatibility run `31043445834`:
865 tests, a 3.049-second restore, 57 official tests, the 36/22 Linux matrix,
Pyrefly, migration round trip, two patches, 167 wheel artifacts, and the unchanged
8/449/0.9947 intrusion result all pass. Image run `31043457794` then passes 864
regressions with one platform skip and builds Server/Host twice for `linux/amd64`
and `linux/arm64`. Each repeated platform Manifest/Config pair matches, with exact
`04bb33a1` product, `8c191ac0` upstream, `p6a000000007` schema, and `0.2.0`
adapter labels. The image-evidence successor wheel requires 168 artifacts.

The image result remains an unpublished candidate archive: it has no registry-
immutable digest, verified keyless signature, protected production workflow,
vulnerability/license admission, digest-pinned canary, or N-1 rollback. It therefore
does not close the P0 image gate, the P6 aggregate, or release `NO-GO`.

The seventh P6 contract slice advances the downstream schema to
`p6a000000008` and introduces a dedicated billing authority without modifying official
Runtime tables. It separates Subscription, immutable Pricing Snapshot, fixed-point
Entitlement, immutable Usage, rebuildable Balance, Reservation, append-only Customer
Ledger, append-only Provider Cost Ledger, and immutable Reconciliation facts. Monetary
amounts use integer minor units and quantities use bounded Decimal values; the database
enforces Reservation and ledger conservation, immutable-fact triggers, Tenant scope,
unique external identities, and `ENABLE + FORCE RLS`.

The `saas_billing` role receives the minimum billing and Outbox privileges and read-only
Tenant/member metadata. It cannot read Prompt, code, Project content, Runs, Secrets, or
credentials; `saas_app` and `saas_governance` receive no temporary billing-table access.
The existing `/saas/admin/projects` console gains one content-blind Tenant Billing view
for Subscription, Pricing, Entitlement, Usage/Ledger inspection, and Reconciliation.
It deliberately exposes no Credit, Usage, Reserve, Settlement, Refund, or Provider Cost
ingestion route. Cookie writes retain authenticated actor, Tenant scope, Origin/CSRF,
permission, idempotency, and optimistic concurrency checks.

The PostgreSQL logical-restore fixture now contains non-empty facts in all ten billing
tables and proves post-backup Subscription suspension and mismatch-resolution replay.
Pricing creation now serializes by Tenant and rejects overlapping plan windows. A
content-blind audit compares the mutable Balance projection with immutable ledger
deltas, and a versioned operator-only repair rebuilds only that projection while
publishing its Before/After receipt. Exact compatibility run `31055362434` at
`7f985c1c1aebdff5370500a7175ce151f9a5d5bb` passes 877 tests, a 3.814-second
PostgreSQL 16 logical restore with 67/17 forced-RLS inventories, 57 official tests,
the 36/22 Linux matrix, Pyrefly, the `p6a000000008` migration round trip, both patch
replays, the 173-artifact implementation wheel, and the unchanged 8-file/449-line/
two-patch intrusion budget. The evidence-successor wheel requires 174 artifacts.

That `p6a000000008` implementation did **not** close P6: non-human metering identity, actual
Run/Provider integration, period rollover, Provider webhook ordering/signature/replay,
real Provider invoice reconciliation, payment/invoice/tax boundaries, production SLO,
and commercial acceptance remain open. See
`saas/production/runbooks/billing-ledger.md`; release remains `NO-GO`.

The eighth P6 contract slice advances the downstream schema to `p6a000000009` and
closes the code-level non-human metering identity and authenticated internal-ingestion
gap. A dedicated `saas_metering` database role can see only the exact live Runner,
`billing_metering` certificate, capability, Dispatch, content-blind Run columns,
Subscription, Pricing, Usage and receipt selected by transaction-local authority facts.
Tenant, Space, Project, actor, session and price are derived by the server; the request
cannot provide any of them. Every accepted Usage fact receives one immutable receipt
binding Runner connection generation, certificate fingerprint, capability, Dispatch
generation, Run fence, idempotency key and request hash, and publishes a secret-free
Outbox event in the same transaction.

The internal transport accepts only TLS 1.3 mutual authentication and one exact
`spiffe://omnigent/runner/{uuid}` URI SAN, rechecks the durable certificate lifecycle,
derives the SHA-256 fingerprint from the presented DER certificate, enforces a bounded
HTTP/1.1 `POST /internal/v1/billing/usage` contract, rejects caller scope and Pricing,
and performs no hidden retry. The logical-restore contract now restores two nonempty
machine receipts plus their Usage/Run/Capability/certificate/Runner dependencies,
proves billing-role cross-Tenant denial, checks the immutable trigger, and reports
68/17 forced-RLS inventories. Local focused acceptance passes 23 metering, billing,
migration, and restore tests. A clean PostgreSQL 16 database then passes the complete
889-test SaaS compatibility matrix in 339.37 seconds; the isolated logical restore
passes in 28.408 seconds, the wheel contains 177 required SaaS artifacts, and full
Pyrefly reports zero errors. That matrix exposed a Project Admin login race in which
the permission catalog could finish before scope discovery. The scope action is now
disabled until discovery completes, and a deterministic Chromium regression delays
the scope response by 750 milliseconds before proving the action cannot submit early.
Exact compatibility run `31063360786` at
`b2285a70b0c78131b043200c4b1cc1ca8536877f` passes 889 tests in 144.76 seconds,
a 3.134-second PostgreSQL 16 logical restore with two linked machine receipts and 68/17
forced-RLS inventories, 57 official tests in 34.33 seconds, the 36/22 Linux security
matrix in 15.14 seconds, Pyrefly, migration round trip, both patch replays, and the
177-artifact implementation wheel. The intrusion result remains 8 files, 449 lines,
two patches, and 0.9953 isolated custom code. The evidence-successor wheel requires
178 artifacts.

Image candidate run `31063360725` is deliberately not accepted as machine-metering
evidence: source inspection found that all four repeated builds still hard-coded the
older `p6a000000007` image label while the authoritative migration head is
`p6a000000009`. The successor resolves the schema revision from
`saas/production/baseline.json`, applies it to every Server/Host attempt, and makes the
supply-chain policy checker reject a missing baseline derivation or any build that
does not consume the resolved value. Corrected image run `31064837882` at
`f75be5a62813b00740334ba701be9633b1dab9e3` passes 888 regressions with one platform
skip, migration round trip, both patch replays, and the 8-file/451-line/0.9953
intrusion budget. It builds Server and Host twice for `linux/amd64` and `linux/arm64`;
each repeated Manifest/Config pair matches, every image label names
`p6a000000009`, and each build carries two attestation descriptors. This closes the
machine-metering executable candidate gap only. The archives are not registry-published
or signed production images, and vulnerability admission, canary, and N-1 rollback
remain open. The evidence-successor wheel requires 179 artifacts.

The next Runtime Partition slice now connects official usage completion to the machine
client without importing SaaS code from official source. Managed Hosts disable the
forkserver, select a reviewed downstream Runner entry module through a generic upstream
seam, claim one scheduler-staged grant per official launch frame, and pass only a
mode-0600 one-time envelope path to the child. The child unlinks and fsyncs that envelope
before official startup. A required upstream-neutral usage sink persists content-blind
input/output facts atomically before a completed response/event can return, then a
background dispatcher retries the TLS 1.3 mTLS endpoint with stable idempotency. Spool
files reject symlinks, changed identity, duplicate/unknown JSON, non-allowlisted meters,
units, attributes and forged event keys; the capability never enters the spool.

Local acceptance exercises the official `Client.responses.create` path, direct and
actual official Host launch frames, crash/restart and partial-delivery replay, fail-closed
disk/envelope behavior, and a complete Provider observer -> private spool -> mTLS ->
durable certificate authorization -> `saas_metering` PostgreSQL RLS -> immutable Usage
receipt chain. Exact compatibility run `31068082417` at
`0e886d503b4fbd12813de3a6034f451e6e3e4e8a` passes 901 tests in 149.00 seconds,
a 6.672-second PostgreSQL 16 logical restore with two linked machine receipts and 68/17
forced-RLS inventories, 57 official tests in 29.88 seconds, the 36/22 Linux security
matrix in 12.76 seconds, Pyrefly with zero errors, migration round trip, both patch
replays, and the 181-artifact implementation wheel. The intrusion result remains within
budget at 9 direct upstream files, 479 net-added lines, two patches, and 0.995 isolated
custom code. The evidence-successor wheel requires 182 artifacts.

This is still a code-level Runtime
composition, not live production billing: the durable scheduler dispatcher must deliver
the raw one-time grant to the selected Host process, the observer currently synthesizes
a request identity because the official callback exposes no Provider-native request ID,
and a process kill between Provider completion and usage notification remains a
reconciliation window. Period rollover, signed/ordered/replay-safe Provider webhooks,
real Provider invoice comparison, payment/tax boundaries, production SLO/capacity and
commercial acceptance remain open. P6 and release remain `NO-GO`.

P0 now has executable baseline and image-candidate controls rather than empty
evidence slots. It deliberately remains `in_progress`: all eleven ADRs and the
three data-class objectives still need the exact-revision approval roles, SLO
dashboards are not live, no immutable tenant/regional restore drill is recorded,
and no signed, vulnerability-cleared, digest-pinned production server/host
image has been promoted through canary and N-1 rollback. Run the structural
checks during development and add `--require-ready` only to a protected
production promotion workflow:

```bash
uv run python -m saas.scripts.check_adr_approvals
uv run python -m saas.scripts.check_production_baseline
uv run python -m saas.scripts.check_recovery_readiness
uv run python -m saas.scripts.check_slo_capacity_readiness
uv run python -m saas.scripts.check_image_supply_chain
uv run python -m saas.scripts.check_production_baseline --require-ready
uv run python -m saas.scripts.check_recovery_readiness \
  --product-revision "$(git rev-parse HEAD)" --require-ready
uv run python -m saas.scripts.check_slo_capacity_readiness \
  --product-revision "$(git rev-parse HEAD)" --require-ready
uv run python -m saas.scripts.check_image_supply_chain \
  --product-revision "$(git rev-parse HEAD)" --require-ready
```

ADR approval is a two-PR evidence flow so generation of the record cannot alter
the commit that people reviewed:

1. Treat `saas/production/adr-approval-policy.json` and
   `adr-approval-authorities.json` as the authority. The active mode is the
   explicitly degraded `sole-owner-risk-waiver`: repository Owner `Dream1216`
   assumes all ADR-owner roles without fabricating independent GitHub Reviews.
   The normal four-person signing rules remain the required replacement before
   production GA or the policy review due date.
2. Open the decision PR with the candidate, policy, authority map, baseline,
   and all eleven ADR documents. Freeze its exact head. In waiver mode the PR
   must be authored and merge-committed by the configured sole Owner, that
   live GitHub identity must retain repository `admin`, and
   `compatibility-gate` must succeed on the exact reviewed head. The waiver
   does not bypass any technical or production verification gate.
3. On a successor evidence branch, export a token with read access and run:

   ```bash
   export GH_TOKEN=<read-only-token>
   uv run python -m saas.scripts.finalize_adr_approval \
     --repository Dream1216/omnigent --pull-request <merged-decision-pr-number>
   ```

4. Reference the generated record from `baseline.json`, set approval to
   `approved`, set all eleven registry statuses to `accepted`, and open
   the evidence PR. CI re-fetches the merged PR, exact-head check run and live
   sole-Owner/admin evidence, verifies all eleven generated technical-owner
   acceptances, and rejects record mutation. Standard four-person mode instead
   re-fetches and verifies every required GitHub Review. Run:

   ```bash
   uv run python -m saas.scripts.check_adr_approvals \
     --verify-github --require-approved
   ```

5. Only after that CI run succeeds may
   `p0-approved-production-adrs-and-owners` move from `pending` to `passed` and
   cite the immutable record and exact CI run. Other P0 blockers remain and the
   overall release stays `NO-GO`.

Run the focused checks:

```bash
uv run pytest tests/saas
uv run pyrefly check saas
uv run python -m saas.scripts.check_acceptance_manifest
uv run python -m saas.scripts.check_patch_queue \
  --output artifacts/patch-replay-report.json
uv run python saas/scripts/check_upstream_delta.py \
  --output artifacts/upstream-delta-report.json
```

Exercise the independent migration against a disposable database:

```bash
export OMNIGENT_SAAS_DB_URL=sqlite:////tmp/omnigent-saas-control-plane.db
uv run alembic -c saas/control_plane/alembic.ini upgrade head
uv run alembic -c saas/control_plane/alembic.ini check
```

Exercise the real PostgreSQL RLS negative test with a disposable PostgreSQL 16
database owned by the URL's user:

```bash
export OMNIGENT_SAAS_TEST_POSTGRES_URL=\
postgresql+psycopg://postgres:postgres@localhost:5432/postgres
uv sync --frozen --extra all --group dev --extra saas
uv run pytest \
  tests/saas/test_postgresql_rls.py \
  tests/saas/test_platform_security_postgresql.py \
  tests/saas/test_execution_postgresql.py \
  tests/saas/test_runtime_postgresql_rls.py \
  tests/saas/test_context_snapshot_postgresql.py \
  tests/saas/test_scheduling_postgresql.py \
  tests/saas/test_webhook_delivery.py
```

## PC1 Platform Security Foundation

The `pc1a00000001` downstream migration adds an independent Staff principal, expiring
role Assignment and phishing-resistant Staff session model plus content-blind Tenant and
Global User projections. The Platform permission catalog declares API, UI and audit
metadata for five built-in roles and has no wildcard or `allow_all` permission. Platform
roles never derive from Tenant Membership.

`create_platform_admin_app` is a standalone, feature-flagged FastAPI application for a
dedicated HTTPS Origin, Audience and `__Host-` cookie. It rejects bearer authentication,
mixed Tenant/Staff cookies, wrong Origin/Audience, unsafe requests without exact Origin,
and stale/revoked Staff authority. Its first read-only endpoints expose context,
permissions, stable-cursor Tenant/User projections and logout; mutation APIs remain
closed until governed Admin Operations are implemented.

PostgreSQL uses four independent least-privilege roles for Staff authentication,
browser reads, governance and projection writes. None inherits the emergency
`saas_platform` role. All five PC1 tables use forced RLS, bringing the control-plane
inventory to 73 tables; the isolated logical restore hashes and verifies non-empty PC1
facts at the exact migration head. See
`saas/production/runbooks/platform-security.md` for deployment, bootstrap, incident and
rollback procedures. These code contracts are PC1 only and do not claim a complete
Platform Console or production GO.

Exact implementation successor `07b368033d91aa4fe4d3e649b4c3dccd358f3e0e` is
verified by compatibility run `31187073403`: 934 combined tests, a 3.173-second
PostgreSQL 16 isolated restore with the 73/17 forced-RLS inventories, 57 official
zygote/query-context regressions, the 36-pass/22-platform-skip Linux security matrix,
Pyrefly with zero errors, the `pc1a00000001` migration round trip, both patch replays,
and the 187-artifact implementation wheel. The direct-upstream budget remains 9 files,
479 net lines and two patches, with a 0.9952 isolated-code ratio. The first implementation
run failed closed on a real sync-Playwright/asyncio process-ordering conflict; the
successor runs both Admin Chromium suites outside pytest-asyncio's main thread.

This evidence does not activate a production Staff IdP or Platform Origin, and it does
not implement PC2 User/Tenant lifecycle, PC3 governed support/evidence, PC4 Platform UI,
or PC5 enterprise operations. The P0-P6 ledger therefore remains at eleven pending
aggregate gates and release `NO-GO`.

Image candidate run `31187141816` verifies the same exact SHA with 933 tests and one
platform skip. Server and Host each build twice for both `linux/amd64` and `linux/arm64`;
all repeated platform Manifest/Config pairs match and bind exact Product, Upstream,
Schema and Adapter labels. The archived candidates are not registry-published, signed,
scanned, canaried, or rollback-proven, so they do not close the P0 production image gate.

## PC2 lifecycle and P6 period-close implementation candidate

The downstream head `pc2b00000001` builds on PC1 without modifying the official
Agent/Harness loop. `pc2a00000001` adds a Tenant lifecycle version and immutable
Platform lifecycle receipts. `PlatformLifecycleService` now provides fresh-auth,
approval-bound, versioned and idempotent Global User suspend/restore, all-Session
revocation, Tenant suspend/restore and inactive-Owner recovery. Suspension revokes
human Sessions and active API Credentials and suspends affected Service Accounts;
restore never resurrects old credentials. The standalone Staff application exposes
these commands through its independent Cookie/Origin/CSRF Realm, while PostgreSQL
binds the governance role to the exact target User or Tenant and an active
`platform_operator` assignment.

`pc2b00000001` adds a content-blind Identity Conflict Case queue and a two-stage
review contract. An active `platform_operator` may assign one active Global User
candidate or block the case, but the Staff Realm cannot read the raw email, Issuer or
Subject and can never create an Identity Connection. An assigned candidate must
reauthenticate in the customer Realm and explicitly approve or reject the existing
self-service challenge. Every Staff decision is versioned, idempotent, approval-bound,
target-bound by PostgreSQL RLS and recorded in the immutable lifecycle/Outbox trail.
Downgrade refuses to erase any accepted PC2 review or audit fact.

`p6b000000001` adds an immutable billing period-close checkpoint. A close requires an
ended interval, its exact reconciliation, no open mismatch and no active/reserved work
on matching periodic Entitlements. The same transaction resets drained counters,
advances each day/month bucket, appends a deterministic close-evidence hash and emits
the idempotent `billing.period.closed` Outbox event. The Tenant Billing HTTP surface can
request and list closes but still cannot mint Credit, Usage, Provider Cost, Settlement
or Refund facts.

The policy catalog is now `2026-08-08.pc2-conflict` with 26 Platform
permissions, and the forced-RLS inventory is 75 control-plane plus 17 Runtime tables.
The implementation includes SQLite migration round trips, Cookie/CSRF and real
Chromium checks, version/idempotency/impact tests, plus PostgreSQL 16 target-bound RLS,
immutability and cross-Tenant tests. Exact compatibility run `31201598950` at
`2d92d02fa02b1e418967c91d67e3eccc59659540` passes 943 tests, a 3.641-second isolated
logical restore, 57 official regressions, the 36/22 Linux security matrix, Pyrefly,
the `p6b000000001` migration round trip, two patch replays, the 192-artifact
implementation wheel, and the 9-file/479-line/0.9953 intrusion result. That predecessor
restore fixture contains zero period-close rows and therefore remains evidence only for
the earlier slice.

The current implementation candidate extends the isolated logical-restore fixture with
two immutable period-close facts: one is present in the backup and one is applied by
the deterministic post-backup replay. The restored database must retain both exact
Tenant/Reconciliation links, expose only the current Tenant through RLS, retain the
immutability trigger and match selected-table hashes. Exact compatibility run
`31211571929` at `cc9536094ff71eff1e7513198de878e3cd038491` passes 946 tests in
173.45 seconds, the 3.713-second PostgreSQL 16 restore with one backed-up and one
post-backup replayed close fact, 57 official regressions, the 36/22 Linux security
matrix, Pyrefly with zero errors, the `pc2b00000001` migration round trip, both patch
replays, and the 195-artifact implementation wheel. The restored selected-table hash is
`f6727575856fc5fe0e6e24a91e0faa4eace75280794c6d6dc97e57eab7c5750c`; the forced-RLS
inventory remains 75 control-plane plus 17 Runtime tables, and source intrusion remains
inside budget at nine files, 479 lines, two patches and a 0.9954 isolated-code ratio.
This accepts the exact PC2 Identity Conflict and P6 nonempty logical-restore code slice;
its executable-image facts are verified separately by the exact-SHA image run below.

Image candidate run `31211571817` verifies the same exact SHA with 945 tests and one
platform skip. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
all repeated platform Manifest/Config pairs match, bind Product `cc953609`, Upstream
`63035f92`, Schema `pc2b00000001` and Adapter `0.2.0`, and contain two attestation
descriptors per build. These archives are not registry-published, signed,
vulnerability/license-cleared, canaried, or N-1-rollback proven. They are accepted
reproducible candidate-image evidence, not production image promotion. The two new
machine records bring the evidence-successor wheel requirement to 197 artifacts.

Predecessor image candidate run `31202057865` verifies
`2d92d02fa02b1e418967c91d67e3eccc59659540` with 942 tests and one platform skip.
Server and Host each build twice for `linux/amd64` and `linux/arm64`;
all four repeated platform Manifest/Config pairs match exact Product, Upstream, Schema
and Adapter labels and include two attestation descriptors per build. These archives
are not registry-published, signed, vulnerability/license-cleared, canaried, or
N-1-rollback proven, so this is accepted candidate evidence rather than production
image promotion. The evidence-successor wheel requires 194 artifacts.

This slice does not complete destructive User/Tenant deletion. It does not implement
PC3 governed support and signed audit,
PC4 `/platform-admin` UI acceptance, PC5 enterprise/operations completion, Provider-native
Receipt/Kill-Window recovery, payment, invoice or tax integrations. The 11 aggregate
production gates and release `NO-GO` remain unchanged.

## PC3 governed Support and audit-evidence verified candidate

The downstream head `pc3a00000001` adds six isolated platform tables for versioned
Admin Operations, Tenant-bound JIT Support Grants, opaque one-time Support Sessions, a
serialized hash-chain head, immutable Audit Events and signed Audit Exports. It does
not modify the official Agent/Harness loop. The forced-RLS inventory is now 81
control-plane tables plus the existing 17 Runtime tables.

Standard Support access has a one-hour maximum and requires fresh approval from an
active Tenant Owner/Admin/Security Auditor followed by a different Staff approver.
Break-glass has a 15-minute maximum and mandatory incident reference; it skips only
customer pre-approval and still requires separation of duties. Both modes bind exact
Tenant, scope, expiry and optional Project IDs. The short-lived Support token is shown
once, persisted only as a SHA-256 digest, and can be validated only through the
independent `saas_platform_support` role. That role neither inherits nor can `SET ROLE`
to the emergency `saas_platform` authority.

The Staff application exposes request/list/approve/reject/revoke/session endpoints and
content-blind Admin Operation/Audit queries. The Tenant Cookie application exposes
Grant metadata plus approve/reject/immediate-revoke controls; it rechecks Global User
status, session security version and active Tenant role. Every accepted transition,
session issuance and revocation commits its redacted Outbox fact and hash-chained audit
event in the same transaction. The permanent empty chain head serializes the first
writer, and PostgreSQL triggers reject mutation or deletion of Audit Events/Exports.

Audit Export requires an authorized auditor request and a distinct Staff approval.
`AuditSigner` is the production abstraction for an external KMS/HSM HMAC-SHA256 key;
the in-process `AuditSigningKey` exists only for deterministic local acceptance. A
production plaintext signing key, missing KMS identity/rotation proof, or unverified
chain/export signature remains a release blocker.

Implementation commit `c8ce9e75775ff8964905bbab1d8f6fcf875b5f6b` first exposed
that the workflow intentionally reused one PostgreSQL database across migration tests:
immutable PC3 audit facts correctly blocked a later downgrade. Test-isolation successor
`df7ce571910bd0c4c727784cd4a27f8fbfb97ce3` removes only the fixture's PC3 facts as
the test superuser and returns the schema to PC2 without weakening product roles,
immutability triggers or the nonempty downgrade guard.

Exact-successor compatibility run
[`31223549606`](https://github.com/Dream1216/omnigent/actions/runs/31223549606)
passes 951 tests, 57 official tests, 36 hard-sandbox tests with 22 platform skips,
Pyrefly with zero errors, PostgreSQL 16 forced-RLS checks for 81 control-plane and 17
Runtime tables, `base -> pc3 -> no drift -> base`, wheel inspection and two patch
replays. Exact-successor image run
[`31223584072`](https://github.com/Dream1216/omnigent/actions/runs/31223584072)
passes its 950-test suite with one platform skip and independently reproduces Server
and Host OCI archives for amd64 and arm64 with matching manifests/configs and two
attestation descriptors per build.

These records close only the PC3 code, exact-SHA compatibility and reproducible-image
candidate subchecks. The restored database contained the PC3 schema and policies but
no nonempty Support Grant, Session, Admin Operation, Audit Event or Export fact. The
archives are not registry-published, signed, vulnerability/license-cleared, canaried
or N-1 rollback proven. Production KMS/HSM signing and rotation evidence, live Staff
and Tenant approval operations, PC4 exact-SHA acceptance, deployed Origins/IdPs,
multi-AZ/PITR and all aggregate production gates remain open. Release therefore remains
`NO-GO`.

## PC4 Platform Console exact-SHA candidate

The standalone Staff application now serves `/platform-admin` from its dedicated
Cookie/Origin/CSRF Realm. The static HTML, CSS and JavaScript are packaged with the
isolated SaaS boundary and do not modify or embed the official Agent/Harness Web UI.
The Console exposes Overview, content-blind User and Tenant projections, Identity
Conflict review, governed Support access, Audit Evidence and a unified Operations
drawer. Navigation, fields and action buttons are driven by the server permission
catalog; a role-less Staff principal receives an authenticated shell with every
privileged module disabled rather than acquiring default access.

User and Tenant lifecycle forms fetch an exact target-bound authoritative preview
immediately before mutation and submit its current CAS version. Operations merge PC3
approval workflow records with only the caller's immutable PC2 lifecycle receipts;
the merge does not broaden lifecycle audit visibility. Destructive deletion remains
absent. Unsafe requests require the platform CSRF value that the login adapter places
in `sessionStorage["omnigent.platform.csrf"]`; the HttpOnly `__Host-` session cookie is
never exposed to JavaScript. The page has no inline script, third-party asset, dynamic
HTML injection or inline style dependency and runs under same-origin-only CSP.

Real Chromium acceptance covers `platform_operator`, `compliance_operator`,
`support_agent` and role-less Staff against a live HTTPS server, including User CAS
suspension, Identity Conflict blocking, break-glass approval, one-time Support token
handling, audit-export request/two-person signed approval and the unified Operations
view.

Exact implementation commit `90c0334eb9ff01a930d7e94589ec458a98107d6f` is archived
by compatibility run `31230374740`: 954 tests pass in 181.93 seconds, the PostgreSQL 16
logical restore completes in 3.823 seconds with 81/17 forced-RLS inventories, 57
official regressions pass in 38.92 seconds, and the Linux hard-sandbox matrix records
36 passes plus 22 platform skips in 17.49 seconds. Pyrefly reports zero errors, the
migration round trip has no drift, both downstream patches replay, and the 206-artifact
implementation Wheel passes. Source intrusion remains nine files, 479 lines, two
patches and a 0.9957 isolated-code ratio.

The same exact SHA image run `31230374738` passes 953 tests plus one platform skip in
217.04 seconds. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
all repeated Manifest/Config pairs match, labels bind exact Product `90c0334e`, Upstream
`63035f92`, Schema `pc3a00000001` and Adapter `0.2.0`, and every build carries two
attestation descriptors. The archives remain unpublished and are not signed,
vulnerability/license admitted, canaried or N-1 rollback proven. Production Origin/IdP,
external KMS signing, customer-approved live Support, observability and every aggregate
production gate remain open; release remains `NO-GO`.

## PC5 enterprise SCIM convergence foundation

The foundation began at `pc5a00000001`; Bulk receipts and bounded overlapping credential
rotation advance the current local head to `pc5a00000003`. It provides Tenant-owned,
hash-credentialed SCIM
directories, User/Group resource mappings and
immutable provisioning receipts under 85 control-plane plus 17 Runtime forced-RLS
tables. Directory issuance and credential rotation require authentication no older than
five minutes, return the bearer only once under `Cache-Control: no-store`, and persist
only its digest and safe prefix. Immediate rotation uses a version CAS and invalidates
the old credential in the same transaction. Scheduled rotation reveals one successor
token once, activates it no more than 30 days later and keeps the prior token for a
bounded 60–86400-second grace window. Authentication enforces both time boundaries;
the next mutation atomically compacts an expired predecessor before issuing another
successor. Disable uses version CAS, destroys both active and successor digests, and
immediately removes all bearer authority; all transitions persist a
secret-free idempotency receipt and replay without returning the token. Provisioning
never treats email equality as identity proof. A User deprovision
revokes Tenant, Space, Project, exact Resource, enterprise Group and active Session
access; a managed Owner is suspended and flagged for Owner Recovery rather than leaving
interactive access or silently transferring ownership. Group convergence refuses to
re-add an inactive User, so a late Group update cannot undo a newer deprovision.

The HTTP adapter exposes ServiceProviderConfig and a bounded SCIM 2.0 subset:
POST/GET-by-id/PUT/PATCH/DELETE plus ListResponse for Users and Groups, bounded Bulk, weak
ETags/If-Match, bearer authentication and `application/scim+json` responses. Collection reads use stable
one-based pagination, a maximum count of 100, a 1,024-character/16-term/four-level
filter budget and deterministic allowlisted sorting with UUID tie-breaking. The bounded
grammar supports `and`/`or`/`not`, `eq`/`ne`/`co`/`sw`/`ew`/`pr` over resource-specific
attributes, escapes SQL wildcard input and converts nullable comparisons to SCIM
two-valued behavior; every query remains bound to the exact authenticated Directory.
Tenant management routes expose fresh-authenticated, idempotent Directory immediate
rotation, scheduled overlap rotation and disable with one-time token delivery. PUT performs guarded full
replacement without changing `externalId`; DELETE retains an inactive tombstone while
revoking User access or archiving Group authority. Resource-specific Add/Replace/Remove
PATCH paths and lost-response replay execute under one replay-before-CAS transaction.
Bulk accepts at most 32 operations and 1 MiB, supports User/Group POST/PUT/PATCH/DELETE,
resolves backward and forward `bulkId` dependencies, rejects circular/unresolved graphs,
honors `failOnErrors`, and stores immutable request/result receipts for exact replay. Full
RFC filter attributes/operators/value paths, complete RFC PATCH paths, larger/provider-
specific Bulk profiles, automated IdP rollout telemetry, SAML/enterprise OIDC activation,
Domain Claim, JIT, MFA and recovery policy remain explicit PC5 work. Directory/subject
state and identity Event Receipts are now separate deletion
surfaces with token-hash destruction, subject erasure and non-resurrecting receipt
anonymization checks. The anonymization/Legal Hold workflow is not implemented yet and
immutable receipts may still carry external identity/display fields, so Privacy remains
a production blocker rather than a completed property. Local evidence currently consists
of eight convergence/lifecycle tests, five HTTP tests, SQLite model/migration checks, one
isolated PostgreSQL 16 token-RLS/rotation/disable/list/concurrent-CAS/Bulk-lock/immutable-event test and a 79.649-second
nonempty logical restore covering two Tenant-isolated Directory/User/Group/Event fact sets. Exact
implementation commit `e71a46652a153e9e23f5b3959de59f375cf9a89e` is archived by
compatibility run `31233595734`: 960 tests pass with 232 existing warnings in 188.36
seconds, the PostgreSQL 16 logical restore completes in 4.144 seconds with 85/17
forced-RLS inventories and two Tenant-isolated SCIM fact sets, 57 official regressions
pass in 38.91 seconds, and the Linux hard-sandbox matrix records 36 passes plus 22
platform skips in 17.19 seconds. Pyrefly reports zero errors, the migration round trip
has no drift, both downstream patches replay, and the 212-artifact implementation Wheel
passes. Source intrusion remains nine direct files/479 lines with a 0.9958 isolation
ratio. Artifact `9014716414` contains the exact machine reports.

The same exact SHA image run `31233595699` passes 959 tests plus one platform skip in
188.65 seconds. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
all repeated Manifest/Config pairs match, labels bind exact Product `e71a4665`, Upstream
`63035f92`, Schema `pc5a00000001` and Adapter `0.2.0`, and every build carries two
attestation descriptors. Artifact `9015030365` has digest
`7f12d12fcda35386b8a61a5855746fd21bf8723d1d21527e154bc0b715b2024c`.
The archives remain unpublished and are not signed, vulnerability/license admitted,
canaried or N-1 rollback proven. All omitted protocol, privacy, federation, operations
and production gates remain open; this is not PC5 completion or production proof.

The second PC5 implementation `226dc6d8b3b90faf35d12d1aa499506654be3797`
closes the isolated Directory credential rotation/disable code subcheck. Exact
compatibility run `31239595356` passes 985 tests with 232 warnings in 172.49 seconds,
a 6.015-second PostgreSQL 16 logical restore with 85/17 forced-RLS inventories and two
Tenant-isolated SCIM fact sets, 63 official regressions, the 39-pass/22-platform-skip
Linux matrix, Pyrefly, migration round trip, two patch replays and the 216-artifact
implementation Wheel. Artifact `9016637067` has archive digest
`df9629a91dd231ba4261232f7d1426bfe1a941c7aef33b32b787afcb42147d62`.

Exact image run `31239616246` passes 984 tests plus one platform skip in 189.55 seconds.
Server and Host each build twice for `linux/amd64` and `linux/arm64`; repeated platform
Manifest/Config facts match, every label binds Product `226dc6d8`, Upstream `9dab48b4`,
Schema `pc5a00000001` and Adapter `0.2.0`, and every build carries two attestation
descriptors. Artifact `9016902247` has archive digest
`471db65a5d4c3972f2d576d4273e4a9ca14db2921f8fc04e91a49457405e2ed7`.
These are unpublished candidates, not registry publication, signature, scan, Canary,
N-1 rollback, complete SCIM/federation/privacy behavior, PC5 completion or release `GO`.

The third PC5 implementation `29c815e7d34f5d8674aebe06740a35131f416598`
adds Directory-scoped User and Group collection reads.
`startIndex` is one-based, `count` is bounded from zero through 100, ordering is stable,
and the adapter accepts only one strict `eq` filter over the resource-specific allowlist.
Unsupported, compound, malformed and over-limit requests fail with SCIM error payloads;
User-name comparison is normalized, Group filters cannot use User attributes, and both
SQLite and real PostgreSQL checks assert that the token-selected Directory remains the
query boundary. Exact compatibility run `31242675519` passes 987 tests with 232 warnings
in 194.86 seconds, a 4.027-second PostgreSQL 16 logical restore with 85/17 forced-RLS
inventories and two Tenant-isolated SCIM fact sets, 63 official regressions, the
39-pass/22-platform-skip Linux matrix, Pyrefly, migration round trip, two patch replays
and the 218-artifact implementation Wheel. Artifact `9017571045` has archive digest
`1d4d7c62a1e75beacdcaf51f4d3f1f2c7e00b673f1a8ed69f7fca280e3316918`.

Exact image run `31242683505` passes 986 tests plus one platform skip with 232 warnings
in 200.75 seconds. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
repeated Manifest/Config facts match, every label binds Product `29c815e7`, Upstream
`9dab48b4`, Schema `pc5a00000001` and Adapter `0.2.0`, and every build contains two
attestation descriptors. Artifact `9017915363` has archive digest
`94081a3587406d32c044974f6e3eb1fdae08ae5e15c7b5c37f08f1d911571d4d`.
This closes only the ListResponse and bounded equality-filter code, exact-SHA
compatibility and unpublished image candidate subchecks. PUT/DELETE/Bulk, general filter
grammar, sorting, complete PATCH, lost-response replay, overlapping credential rotation,
federation, privacy, production promotion and all eleven aggregate gates remain open.

The fourth PC5 implementation `626841b1bb8544fe8d3784b828c27193f7df7396`
adds guarded User/Group PUT, retained-tombstone DELETE and resource-specific
Add/Replace/Remove PATCH paths. The service authenticates one Directory, checks immutable
event replay before locking the exact resource, then applies ETag CAS, derives the next
source version and persists the converged state plus Event/Outbox in one transaction.
Consequently a lost response retried with the same key, payload and old ETag returns the
committed result without another mutation; a changed payload conflicts, while a different
key with a stale ETag returns 412. PostgreSQL 16 runs two transactions against one User
version and proves exactly one winner and one CAS loser. `externalId` is immutable, User
deletion keeps deprovision precedence and Owner Recovery, and Group deletion archives the
mapped authority and removes active members.

Exact compatibility run `31246087422` passes 989 tests with 232 warnings in 186.11 seconds,
a 3.798-second PostgreSQL logical restore with 85/17 forced-RLS inventories and two
Tenant-isolated SCIM fact sets, 63 official regressions in 40.31 seconds, the
39-pass/22-platform-skip Linux matrix in 17.49 seconds, Pyrefly, migration round trip, two
patch replays and the 220-artifact implementation Wheel. Artifact `9018593020` has archive
digest `14b2fb49f0f87b13dc19f8b561c56d5db547686ada64a9925caba67c5945a384`.

Exact image run `31246057815` passes 988 tests plus one platform skip with 232 warnings in
183.93 seconds. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
repeated Manifest/Config facts match, every label binds Product `626841b1`, Upstream
`9dab48b4`, Schema `pc5a00000001` and Adapter `0.2.0`, and every build contains two
attestation descriptors. Artifact `9018836641` has archive digest
`5474cec818f0c6f946defdba7c91629cc7e4ff98b53040f514eb91cfc68fd5e5`.
This closes only the bounded resource lifecycle, replay-before-CAS code, exact-SHA
compatibility and unpublished image-candidate subchecks. Bulk, general/compound filters,
sorting, complete RFC PATCH path/value grammar, overlapping credential rotation,
federation, privacy, production promotion and all eleven aggregate gates remain open.

The fifth PC5 implementation `3d1f56778f61090fa3b0e0f26a100e14f8279bab`
adds a bounded compound filter grammar and deterministic sorting to both User and Group
collections. Filters are capped at 1,024 characters, 16 comparison terms and four
parenthesis levels; `not`, `and` and `or` follow protocol precedence, while `eq`, `ne`,
`co`, `sw`, `ew` and `pr` are restricted to each resource's scalar allowlist. Client
wildcards are escaped before SQL comparison, missing attributes keep two-valued filter
semantics, and sorting uses a UUID tie-breaker with protocol-compatible missing-value
placement. The authenticated Directory remains the outer predicate for every query.

Exact compatibility run `31249990283` passes 989 tests with 232 warnings in 186.16
seconds, a 3.895-second PostgreSQL 16 logical restore with 85/17 forced-RLS inventories
and two Tenant-isolated SCIM fact sets, 63 official regressions in 39.75 seconds, the
39-pass/22-platform-skip Linux matrix in 18.27 seconds, Pyrefly, migration round trip,
two patch replays and the 222-artifact implementation Wheel. Artifact `9019748005` has
archive digest `62fd99742e5d563ef16c774e9e511fde4dcac4b5855da612122babb99de39d24`.

Exact image run `31250015114` passes 988 tests plus one platform skip with 232 warnings
in 190.17 seconds. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
repeated Manifest/Config facts match, every label binds Product `3d1f5677`, Upstream
`9dab48b4`, Schema `pc5a00000001` and Adapter `0.2.0`, and every build contains two
attestation descriptors. Artifact `9020044923` has archive digest
`9a4befd83bb5bb422a4cf1a4dd3ee7c09bd472e16ae7a413710463e5dd5e258b`.
This closes only the bounded compound-filter and deterministic-sort code, exact-SHA
compatibility and unpublished image-candidate subchecks. Bulk, `gt/ge/lt/le`, complex or
multi-valued value paths, complete PATCH grammar, overlapping credential rotation,
federation, privacy, production promotion and all eleven aggregate gates remain open.

The sixth PC5 code slice implements the bounded RFC 7644 Bulk profile and advances the
schema to `pc5a00000002`. ServiceProviderConfig advertises 32 operations and a 1 MiB
payload ceiling. Request order is preserved across dependency scheduling: forward and
backward `bulkId` references are resolved before dependent work, circular or unknown
references become per-operation 409 results, and `failOnErrors` stops further processing
at the declared threshold. A required top-level `Idempotency-Key` is hash-bound to the
entire normalized request. Immutable Bulk request and result Events make a lost response
replay exact; deterministic child Event IDs resume work committed before an interrupted
batch. PostgreSQL uses a Directory/key session advisory lock held on a dedicated
connection across request claim, child commits and final receipt, so concurrent replicas
cannot execute one Bulk key in parallel. The protocol remains deliberately non-atomic,
as RFC Bulk reports each operation independently. Local SQLite and real PostgreSQL tests
cover replay conflicts, interruption recovery, dependency ordering, payload/operation
limits and multi-session serialization.

Exact compatibility run `31254116952` passes 991 tests with 232 warnings in 171.74
seconds, a 3.842-second PostgreSQL 16 logical restore with 85/17 forced-RLS inventories
and two Tenant-isolated SCIM fact sets, 63 official regressions in 33.90 seconds, the
39-pass/22-platform-skip Linux matrix in 14.74 seconds, Pyrefly with zero errors, a
drift-free migration round trip, two patch replays and the 225-artifact implementation
Wheel. Artifact `9020926068` has archive digest
`55cb74ad63d1418a85d274875fb6facf9698d99f682b7161e00cac21b709a933`.

Exact image run `31254116960` passes 990 tests plus one platform skip with 232 warnings
in 193.98 seconds. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
repeated Manifest/Config facts match, every label binds Product `a484bcfe`, Upstream
`9dab48b4`, Schema `pc5a00000002` and Adapter `0.2.0`, and every build contains two
attestation descriptors. Artifact `9021152363` has archive digest
`8ac5791ff94c330a9def460486dd740fa9b36221dae35dea0e6ea8cadcf079db`.
This closes only the bounded Bulk code, exact-SHA compatibility and unpublished
image-candidate subchecks. Comparison filters, full PATCH value paths, rotation overlap,
federation, privacy, production promotion and all eleven aggregate gates remain open.

The seventh PC5 code slice advances the schema to `pc5a00000003` and adds bounded
scheduled/overlap Directory credential rotation without weakening immediate rotation.
`POST .../rotate-overlap` requires fresh authentication, permission, expected-version
CAS and a hash-bound idempotency key. Activation may be current or at most 30 days in
the future; grace is restricted to 60–86400 seconds. The successor token is returned
once under `no-store`, while only its digest, safe prefix and UTC boundaries persist.
Before activation the successor is denied; during grace both digests resolve only the
same Directory/Tenant; at expiry the predecessor is denied. A later rotation compacts
the expired successor into the active slot in the same locked transaction, while
Disable destroys both slots immediately. An in-progress overlap blocks another rotation,
and downgrade to `pc5a00000002` fails closed while a successor exists. SQLite/HTTP,
real PostgreSQL RLS and a nonempty logical restore fixture cover activation, overlap,
expiry, compaction, idempotent replay, payload conflict, hash non-disclosure, successor
RLS lookup, disable and downgrade refusal.

Exact compatibility run `31257782799` verifies implementation `43569c8c`: 994 tests pass
with 232 warnings in 189.68 seconds, the PostgreSQL 16 logical restore completes in
3.908 seconds with schema `pc5a00000003`, 85/17 forced-RLS inventories, two
Tenant-isolated SCIM fact sets and one active successor fixture, 63 official regressions
pass in 41.28 seconds, and the Linux matrix records 39 passes plus 22 platform skips in
17.31 seconds. Pyrefly reports zero errors, migrations round trip without drift, both
patches replay, and the Wheel contains 228 required artifacts. Artifact `9021950175` has
archive digest `5f5dae29b7ed64aa76614b0b84e3c0b142c4d21c033df847526314ab3d67803c`.

Exact image run `31257782706` passes 993 tests plus one platform skip with 232 warnings
in 192.61 seconds. Server and Host each build twice for `linux/amd64` and `linux/arm64`;
repeated Manifest/Config facts match, every label binds Product `43569c8c`, Upstream
`9dab48b4`, Schema `pc5a00000003` and Adapter `0.2.0`, and every build contains two
attestation descriptors. Artifact `9022168960` has archive digest
`62e6cd3d72c6adb3946f23a7c2b770de1c9dc2e4ec4105799d9272b54b09c412`.
This closes only bounded credential-overlap code, exact-SHA compatibility and
unpublished image-candidate subchecks. Production IdP rollout/clock evidence, full
Filter/PATCH, federation, privacy, production promotion and all eleven aggregate gates
remain open.

The next upstream compatibility slice accepts official `9dab48b4`, 23 commits and 64
files after `63035f92`, without a merge conflict. Upstream now launches each Runner in
the session workspace, recovers cleanly after a failed snapshot, isolates malformed
snapshot metadata and skips bubblewrap masks that target escaping symlinks. It also
forwards `SSH_AUTH_SOCK` for local Hosts. The managed composition keeps that upstream
local behavior outside SaaS while failing closed on both `SSH_AUTH_SOCK` and
`KUBECONFIG`, since either path confers signing or cluster authority to a tenant process.

Exact corrected revision `59562d32e807caa0d38fb71d4a4975ef13d7f8fc` is verified by
compatibility run `31236956326`: 983 tests pass with 232 warnings in 189.58 seconds,
the PostgreSQL restore completes in 4.294 seconds with 85/17 forced-RLS inventories and
two Tenant-isolated SCIM fact sets, 63 official regressions pass, and the Linux security
matrix records 39 passes plus 22 platform skips. Pyrefly reports zero errors, migrations
round trip without drift, both patches replay from the clean official tree, the wheel
contains 214 required artifacts and source intrusion stays within budget at nine files,
485 lines, two patches and a 0.9958 isolated-code ratio. Image run `31236978641` passes
982 tests plus one platform skip and reproduces Server/Host Manifest and Config facts
across two `linux/amd64` and `linux/arm64` builds. All labels bind Product `59562d32`,
Upstream `9dab48b4`, Schema `pc5a00000001` and Adapter `0.2.0`, with two attestation
descriptors per build. The images remain unpublished candidates and do not change the
eleven pending aggregate gates or release `NO-GO`.

The next low-intrusion synchronization merges official `de8aee826c48d632ce335a702f2cca2f6240a6b9`
at `0453d9cf` and rebinds the permanent compatibility contract at `af8a46fd`. The three
new official commits cover Claude-native transcript cursor resumption, generic ACP
authentication environment declaration and package-root skill injection. The downstream
patch queue still contains two clean-tree-replayable patches, and the official regression
matrix now explicitly includes the changed ACP, spawn-environment, runner-skill and
Claude-native forwarder tests.

The eighth PC5 implementation `53f81e1dfd9907e8b4cd592dbe51a70f86148d23`
adds one shared bounded RFC 7644 syntax layer for collection Filter and PATCH paths.
User and Group scalar filters now accept schema-qualified paths, JSON `null` and all
locally meaningful `gt/ge/lt/le` comparisons in addition to the existing operators.
Boolean ordering and a numeric literal compared with a persisted string fail with
`invalidFilter`. Group collection reads support both `members[...]` Value Path
expressions and `members.value`; each becomes an active-member correlated predicate
inside the already authenticated active Directory.

PATCH now supports pathless Add/Replace, schema-qualified `attrPath`, `valuePath` and an
optional selected `subAttr` for the persisted User scalar and Group member resource
model. Every operation first transforms one in-memory candidate, so a later invalid
operation rolls the entire request back before the single replay-before-CAS mutation.
Compound member removal, duplicate-safe Add, no-match Remove, exact replay and Bulk
delegation share the same implementation. A semantic no-op retains the ETag while
writing an immutable secret-free no-op Event/Outbox receipt. Group member subattributes
remain immutable as required by the local Group contract; a selected identity may be
removed but not rewritten. Error mapping distinguishes `noTarget`, `mutability`,
`invalidPath`, `invalidSyntax` and `invalidValue`.

Exact compatibility run `31271156219` verifies `53f81e1d` against official `de8aee82`:
997 tests pass with 232 warnings in 177.72 seconds, the PostgreSQL 16 logical restore
completes in 4.067 seconds with schema `pc5a00000003`, 85/17 forced-RLS inventories and
two Tenant-isolated SCIM fact sets, 325 changed-official regressions pass with two
warnings in 60.05 seconds, and the Linux matrix records 39 passes plus 22 platform skips
in 15.60 seconds. Pyrefly reports zero errors, migrations round trip without drift,
both patches replay, and the Wheel contains 230 required artifacts. Source intrusion
stays within budget at nine official files, 490 net lines, two patches and a 0.996
isolated-code ratio. Artifact `9025705851` has archive digest
`89ebc0693e043c8ea997a3eca2210cadb692c21400b39a8a51c567c4c6684230`.

This closes comparison operators and Filter/PATCH Value Path semantics only for the
attributes persisted by the current local User and Group schemas. It does not implement
every optional RFC 7643 complex/multi-valued User attribute or extension schema, nor
federation, privacy, production promotion or any of the eleven aggregate gates. PC5 and
release remain `NO-GO`.

Exact image run `31271156205` passes 996 tests plus one platform skip with 232 warnings
in 190.38 seconds. Server and Host each build twice for `linux/amd64` and
`linux/arm64`; every repeated Manifest/Config pair matches, labels bind Product
`53f81e1d`, Upstream `de8aee82`, Schema `pc5a00000003` and Adapter `0.2.0`, and each
build carries two attestation descriptors. Artifact `9025955208` has archive digest
`5bc8344ed6a144661568cde72afcbe680a2adc704c71acffa88b1fdbf32c8a78` and JSON
digest `0942f179dc9abe46527252df55578460b20a56d9507e95e43cbe273b5feed7b4`.
These remain unpublished candidates, not registry promotion, signature, vulnerability
or license admission, Canary, N-1 rollback, PC5 completion or release `GO`.

The ninth PC5 development slice starts from merged baseline
`e3172687f9b6f0c6a21d08b62776f1efe9932dce` and advances the SaaS migration head to
`pc5b00000001`. It adds governed Legal Holds, versioned User/Tenant deletion Manifests,
opaque OIDC/SCIM identity Tombstones and a one-time SCIM receipt-redaction exception to
the otherwise immutable receipt trigger. Deletion is Preview/CAS-bound and cannot
finalize until all 15 database, object, index, cache, queue, provider, identity,
worktree, webhook, secret, log, ledger and backup surfaces carry valid signed outcomes.
An active Hold, Owner/Steward dependency, nonterminal Run or active Support Grant blocks
the relevant target. Every Hold has a bounded mandatory review deadline; passing that
deadline never releases it implicitly. Finalization persists the exact independent
approval reference and rejects a replay with another approval. Deleted OIDC subjects
and SCIM external IDs cannot provision again.

Privacy PII access is not added to the browser/API Staff governance role. A separate
`NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS` `saas_privacy_executor` inherits content-blind
governance policy evaluation and receives only the additional erasure privileges. FORCE
RLS binds it to the exact Staff principal, target and Manifest; the control-plane/runtime
inventories are now 88/17. HTTP routes use the dedicated Staff cookie, Origin, CSRF,
permission, fresh-authentication and idempotency boundaries.

Targeted SQLite and real PostgreSQL 16 tests pass for Legal Hold review deadlines,
Global User and invitation-email anonymization, password and Session revocation, exact
Tombstone replay denial, SCIM redaction immutability and content-blind role separation.
Each transformed invitation persists its deletion Manifest ID; FORCE RLS rejects the
same anonymous shape under any other Target/Manifest while ordinary Tenant and exact
token invitation reads retain their existing branches.
The isolated logical restore contract also passes with a released Hold, completed
15-surface Manifest with its completion approval, Tombstone and redacted receipt restored
under schema `pc5b00000001`. A clean disposable PostgreSQL database now passes all 503
SaaS tests; the current local compatibility workflow selection passes 1,056 tests, while the
host-appropriate hard-sandbox selection passes 40 with 21 Linux-only variants skipped.
Pre-commit and Pyrefly pass, the migration upgrades/checks/downgrades without drift, the
Wheel contains 274 required artifacts, both downstream patches replay, and source
intrusion remains within budget at 10 official files, 498 net lines, two patches and a
0.9962 isolated-code ratio.

Historical evidence note: the superseded P0 ADR waiver remains append-only history bound
to its former `pc5a00000003` architecture snapshot; it is not active approval evidence
for the 2026-08-24 synchronization candidate. The current candidate must obtain a fresh
exact-main approval record, so neither an additive migration nor old evidence can rewrite
approval history or authorize an unrelated schema branch. The derived production verifier
is structurally valid but still reports 0/10 and `NO-GO`. This remains a development
candidate until an exact committed SHA passes the compatibility and image workflows.
Local restore and test evidence is not a production deletion drill, backup-expiry proof,
IdP rollout or release `GO`.

The first Privacy administration product slice is implemented on
`codex/saas-p1-privacy-admin-ui` without an official-runtime source change. The
policy-only `pc5b00000002` migration adds exact-target, `FOR SELECT` PostgreSQL
policies for the read-only Platform Security Auditor; it does not alter an existing
migration or grant an Auditor write path. The slice separates `platform.privacy.read`
from the existing destructive
`platform.data_request.manage` permission and adds exact-target, cursor-bounded Legal
Hold and deletion Manifest history reads. `platform_security_auditor` can inspect those
content-blind projections but cannot create a Hold or start, update, or finalize a
deletion. The dedicated Staff console exposes the same boundary as a read-only Privacy
evidence desk: an operator must supply an exact Global User or Tenant UUID, after which
the page shows authoritative blockers, Hold history, Manifest history, and all 15
surface outcomes without exposing request reasons, approval references, signatures,
customer content, or direct identity data. The browser never receives the executor
surface-signing capability.

This slice restores target progress after a browser refresh and closes only the first
Privacy UI discovery gap. It does not add a global privacy queue, failure/attempt state,
retry or DLQ controls, backup-expiry purge receipts, a first-class approval object,
production workers, or the DSSE/attestation bridge required for production deletion
proof. A control-plane Manifest, including one marked completed, therefore remains
distinct from qualified production erasure evidence. P1 as a whole and production
release remain `NO-GO`.

The second Privacy development slice advances the migration head to
`pc5b00000003` and replaces the legacy direct deletion write path with governed
operations for Start, Finalize, Surface DLQ replay, and Backup purge replay. A
Compliance Operator can only request an exact target/version snapshot; a distinct,
freshly authenticated Platform Operator decides it. Approval revalidates the
requester's current role and security version and executes the bound mutation in the
same transaction. The retired direct Surface and Finalize HTTP endpoints return `410`.
The Staff UI and API expose content-blind status, stable error codes, versions, hashes,
and timestamps only; executor identity, resource handles, raw errors, signing keys, and
customer content are never returned.

Fifteen per-surface Work Items now use fenced leases, deterministic idempotency,
allowlisted retry classes, bounded exponential backoff, append-only Attempts, and a
governed DLQ replay generation. Backup discovery materializes an exact signed catalog;
Legal Hold, purge deadline, and object lock are rechecked at claim, immediately before
the external adapter call, and at commit. Placing a Hold fails closed while a destructive
lease is active, so it cannot claim protection while a Provider deletion is in flight.
Deletion Start records the post-anonymization User or Tenant version; ordinary Restore
and Finalize both reject an open Manifest, Tombstone, or target-version drift. Every
successful Surface or Backup result must pass canonical DSSE PAE verification with an
active, purpose-bound Ed25519 trust key, exact workload identity, Product/Upstream/
Schema/Adapter revisions, immutable-artifact URI and digest, storage receipt, and KMS
audit receipt digest. Adapter failures use a rotating-key, domain-separated HMAC rather
than a dictionary-testable raw SHA-256.
Logical deletion may finalize while verified Backup retention remains pending, but it
cannot be represented as complete retention until every catalog item has a purge
attestation. The external three-role Manifest attestation remains a production
admission requirement rather than an unreachable operational database shortcut.

Five new tables for approval bindings, Work Items, Attempts, Evidence Attestations, and
Backup retention run with `ENABLE + FORCE RLS`, moving the control-plane/runtime
inventories to `93/17`. The dedicated `saas_privacy_dispatcher` is a
`NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS` role that does not inherit Staff governance or
the PII erasure executor. It can update only allowlisted columns on the exact
target/Manifest work projection, append Attempts, materialize Backup items, and emit one
of eight exact-schema events whose target is an HMAC locator. A separate
`saas_privacy_verifier` login verifies Ed25519 and writes an immutable, attempt-bound
receipt but cannot modify Work, Attempt, Backup, or Outbox state. Database transition
triggers reject `succeeded` or `purged` without that independent receipt. PostgreSQL 18
tests exercise both logins, missing/cross-target denial, column privileges, forged
success rejection, Outbox allowlisting, append-only triggers, Hold races, and cleanup of
disposable databases and login roles.

Migration `pc5b00000003` is deliberately forward-only once any pre-existing Manifest is
backfilled or a new approval/execution/retention fact exists. An application rollback
must retain the new schema and reapply the matching role contract; a schema downgrade is
permitted only on an empty candidate. Production rollback after data exists requires a
reviewed forward migration or an approved restore, never destructive table removal.

This is a local code and isolated-database candidate. The repository still contains no
production Provider/KMS/HSM account, immutable evidence bucket, real backup estate,
cross-region restore drill, or protected exact-SHA CI/image admission for this slice.
Consequently it closes neither the production Deletion gate nor P1 as a whole, and the
release decision remains `NO-GO`.

## P0S9 production Preview authority

The production Preview path is a server-owned child Run over a committed ChangeSet and
a separately heartbeated readonly Worktree. Browser requests contain only the source
`run_id`, the closed `static_web_v1` profile, and an idempotency key; Runner identity,
connection generation, Worktree lease tokens, capabilities, paths, commands, and other
Runner secrets are never browser inputs. The fixed static runtime executes no Worktree
code and serves a closed MIME set through no-follow component traversal, bounded files,
no directory listing, and fixed security headers.

When the child is ready, Control returns a URL whose one-use exchange bearer exists only
in the fragment. A content-blind bootstrap clears the fragment before submitting the
bearer to the same-origin authorize endpoint; the response installs a distinct rotating
HttpOnly session cookie. Exchange, rotation, authorization, and revocation are narrow
PostgreSQL CAS functions. Preview Edge cannot read or mutate session rows directly.

The standalone Preview Owner owns the official `TunnelRegistry`, the Runner WebSocket
lifecycle, and the TLS 1.3 mTLS relay listener. Runner tunnel registration is issued and
revoked only through incarnation-bound SECURITY DEFINER functions that require the
current Runner connection secret and active `runner_control` certificate fingerprint;
the executor has no direct registration-table access. Each relayed request carries the
canonical Preview host and fixed response policy. The receiving Owner re-authorizes the
session hash and host, rebuilds and compares the complete durable Preview grant, then
compares the exact Placement ID, Runner/generation, routing generation, Gateway, and
relay subject before touching its local official Runner session. Revoked sessions,
same-Runner cross-Preview substitution, and any grant or Placement mutation fail closed.

These contracts have local unit and disposable PostgreSQL 16/18 evidence. They do not
replace deployed NetworkPolicy, external PKI rotation, multi-replica failure drills,
authenticated browser E2E, rollback, or protected exact-image admission evidence.

## Official upstream synchronization candidate: `c724c574`

The 2026-09-02 synchronization candidate merges official
`c724c5744593a24130ce6e426f09ba78aa00b23c` into the frozen Runtime candidate
`26ba2667833ca91cd047ac4a44576a67b4f31713`, then replays the self-service onboarding
commits. Textual conflicts were limited to `omnigent/host/connect.py` and `uv.lock`.
The resolved Host path preserves the official caller-provided lifecycle lock while
retaining the managed Host factory seam. Dependency metadata keeps official 0.13.0
groups and the downstream `saas` extra.

A separate semantic audit found that the new official shared read session could bypass
the managed Store session initializer even though Git reported no conflict. Managed
execution now bypasses that shared session whenever an initializer is installed; local
single-user execution continues to use the official shared-read optimization. Focused
SQLite and PostgreSQL tests cover the initializer boundary and cross-workspace denial.

The regenerated three-entry Patch Replay covers exactly `omnigent/db/utils.py`,
`omnigent/host/connect.py`, `omnigent/llms/_usage_observer.py`, and
`omnigent/runtime/agent_cache.py` and applies cleanly to the pinned official revision.
The local Upstream Delta report passes at the current intrusion ceiling with ten direct
official files, 485 net-added official lines, three active patches, no forbidden file
or reverse dependency, and a 0.998 isolated-code ratio. Any additional direct upstream
file or more than 15 net-added official lines must first remove or reduce an existing
intrusion; the budget may not be silently widened.

Advancing the upstream revision invalidates the previous candidate approval binding. The
new candidate is therefore deliberately `review_required`: all eleven ADRs remain
`proposed` until the exact synchronization PR passes protected CI, merges, and produces
a new append-only sole-Owner risk-waiver record. This is governance degradation made
explicit, not an inherited approval. Local Patch Replay, delta, migration, RLS, restore,
SDK, Wheel, regression, or image checks are candidate evidence only. Production N-1,
dual-architecture signed-image admission, Canary, and release `GO` require their own
protected exact-revision evidence.
