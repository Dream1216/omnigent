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

Member-removal composition must use `CompositeRemovalImpactProvider` with an
explicit required-domain set. Project ownership and grants are collected by
`ProjectRemovalImpactProvider`; all non-terminal Runs created by the member are
collected by `ExecutionRemovalImpactProvider`; open/checkpointed ChangeSets and
active, rebuild-pending, or quarantined Worktrees are collected by
`WorktreeRemovalImpactProvider`. Production composition must require all three
domains (`projects`, `runs`, and `worktrees`). A missing required domain fails
at startup; it is intentionally impossible to infer a zero impact from an
unwired provider.

Database roles are deliberately not created by Alembic because managed
PostgreSQL role ownership is an operator concern. After migration, run
`saas/control_plane/postgresql_roles.sql` as the control-plane database owner,
and give each service login exactly one role. Run identity/session endpoints
with `saas_authenticator`, governance workflows with `saas_governance`, runtime
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
control-plane and 17-table runtime forced-RLS, cross-tenant, tombstone, revocation,
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
least-privilege roles; verifies the canonical 50-table control-plane and 17-table
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
does not close that gate, complete Tenant Members management, or change the eleven
pending aggregate gates and release `NO-GO`. The evidence-successor wheel requires
160 artifacts.

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
aggregate gates, complete Tenant Members management, and release `NO-GO` remain
unchanged.

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
  tests/saas/test_scheduling_postgresql.py \
  tests/saas/test_webhook_delivery.py
```
