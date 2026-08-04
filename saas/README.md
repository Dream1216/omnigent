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
- all 21 protected control-plane tables use `ENABLE` and `FORCE ROW LEVEL
  SECURITY` with transaction-local server-chosen Actor/Tenant/Space values.
  The packaged role bootstrap separates `saas_app`,
  `saas_authenticator`, `saas_governance`, `saas_dispatcher`, and break-glass
  `saas_platform`; none has `BYPASSRLS`.

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
routers. Build `SaasHttpIntegration`, pass `integration.auth_provider` and
`[integration.extra_router]` to official `create_app`, then call
`integration.install_middleware(app)` before serving. This keeps HTTP
authentication entirely in the downstream boundary and adds no new
official-source patch.

Database roles are deliberately not created by Alembic because managed
PostgreSQL role ownership is an operator concern. After migration, run
`saas/control_plane/postgresql_roles.sql` as the control-plane database owner,
and give each service login exactly one role. Run identity/session endpoints
with `saas_authenticator`, governance workflows with `saas_governance`, runtime
resolution with `saas_app`, and dispatch workers with `saas_dispatcher`.
After official migrations and Runtime RLS installation, run
`saas/runtime_rls/postgresql_roles.sql` and grant each runtime service login
only `omnigent_runtime_app`. The service login must not own protected tables
and must remain `NOSUPERUSER NOBYPASSRLS`.

This remains a validated implementation slice, not complete production SaaS
proof. The evidence manifest deliberately keeps P0, P1, and P2 in progress:
the local current-revision matrix passes real PostgreSQL control-plane/Runtime
RLS, concurrent Outbox/Owner operations, and real Chromium Project Admin tests;
PostgreSQL 16 remote CI and the aggregate P2 MVP decision are still required.
OAuth/OIDC provider callback verification,
the multi-replica Context Shell/revocation degradation matrix, approved
production ADRs, reproducible signed images, and Service Catalog/SLO/RPO/RTO
evidence are also pending. P3 durable Run authority, P4 multi-failure-domain
execution and Worktree isolation, P5 production recovery, and P6 commercial
governance have not started and must not be inferred from these foundations.

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
  tests/saas/test_runtime_postgresql_rls.py
```
