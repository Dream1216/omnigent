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
   OSS/SaaS regression, digest-only canary, and N-1 requirements. The candidate
   workflow builds twice without publishing; it cannot be mistaken for signed
   production evidence.

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
- all 38 protected control-plane tables use `ENABLE` and `FORCE ROW LEVEL
  SECURITY` with transaction-local server-chosen Actor/Tenant/Space values.
  The packaged role bootstrap separates `saas_app`,
  `saas_authenticator`, `saas_governance`, `saas_dispatcher`, and break-glass
  `saas_platform`; none has `BYPASSRLS`.

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

Member-removal composition must use `CompositeRemovalImpactProvider` with an
explicit required-domain set. Project ownership and grants are collected by
`ProjectRemovalImpactProvider`; all non-terminal Runs created by the member are
collected by `ExecutionRemovalImpactProvider`. A missing required domain fails
at startup. Once Worktree ownership exists, `worktrees` must be added to that
required set before member removal is enabled; it is intentionally impossible
to infer a zero impact from an unwired provider.

Database roles are deliberately not created by Alembic because managed
PostgreSQL role ownership is an operator concern. After migration, run
`saas/control_plane/postgresql_roles.sql` as the control-plane database owner,
and give each service login exactly one role. Run identity/session endpoints
with `saas_authenticator`, governance workflows with `saas_governance`, runtime
resolution with `saas_app`, and dispatch workers with `saas_dispatcher`.
P3 admission/API transactions also use tenant-scoped `saas_app`; execution
workers inherit only `saas_executor`, while event delivery remains isolated in
`saas_dispatcher`.

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
therefore closed, but P4 cannot complete before Worktree/ChangeSet,
Sandbox/Secret/Egress/Preview, two real failure domains, network partition,
and N-1 rollback acceptance.

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

P4 multi-failure-domain execution and Worktree isolation are only partially
implemented; P5 production recovery and P6 commercial governance have not
started. None may be inferred from the P4 scheduling foundation.

P0 now has executable baseline and image-candidate controls rather than empty
evidence slots. It deliberately remains `in_progress`: all eleven ADRs and the
three data-class objectives still need the exact-revision approval roles, SLO
dashboards are not live, no immutable tenant/regional restore drill is recorded,
and no signed, vulnerability-cleared, digest-pinned production server/host
image has been promoted through canary and N-1 rollback. Run the structural
checks during development and add `--require-ready` only to a protected
production promotion workflow:

```bash
uv run python -m saas.scripts.check_production_baseline
uv run python -m saas.scripts.check_image_supply_chain
uv run python -m saas.scripts.check_production_baseline --require-ready
uv run python -m saas.scripts.check_image_supply_chain --require-ready
```

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
uv sync --frozen --extra dev --extra saas
uv run pytest \
  tests/saas/test_postgresql_rls.py \
  tests/saas/test_execution_postgresql.py \
  tests/saas/test_runtime_postgresql_rls.py \
  tests/saas/test_context_snapshot_postgresql.py \
  tests/saas/test_scheduling_postgresql.py
```
