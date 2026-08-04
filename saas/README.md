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
- all 23 protected control-plane tables use `ENABLE` and `FORCE ROW LEVEL
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
proof. P2's current implementation gate passes the local and GitHub PostgreSQL
16 matrices for control-plane/Runtime RLS, concurrent Identity/Outbox/Owner
operations, Binding Saga fault injection, patch replay, and real Chromium
Project Admin tests. OIDC callback verification has an immutable passing CI
record; P0 remains in progress because approved production ADRs, reproducible
signed images, and Service Catalog/SLO/RPO/RTO evidence are pending. The P1
Context Shell/multi-replica/degradation gate now has an immutable passing
PostgreSQL 16 + Chromium CI record, so P1 is complete. P3 durable Run authority,
P4 multi-failure-domain
execution and Worktree isolation, P5 production recovery, and P6 commercial
governance have not started and must not be inferred from these foundations.

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
  tests/saas/test_runtime_postgresql_rls.py \
  tests/saas/test_context_snapshot_postgresql.py
```
