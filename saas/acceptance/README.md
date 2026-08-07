# P0-P6 acceptance evidence

`p0-p6-evidence.json` is the authoritative machine-readable progress ledger.
It deliberately separates implementation evidence from a passed acceptance
gate. A gate may list code and tests while remaining `pending` until the exact
revision has produced the required real infrastructure, browser, recovery, or
external approval evidence.

Run `python -m saas.scripts.check_acceptance_manifest` in CI. A phase cannot be
marked `complete` while any gate is pending, and the release cannot be marked
`GO` until every P0-P6 phase is complete.

Immutable CI records name the verified GitHub Actions run and exact source
revision. `p2-ci-30883002639.json` records the first complete P2 implementation;
`p2-upstream-sync-ci-30883850613.json` records the next official-baseline sync,
including patch shrinkage, expanded official regression tests, and renewed
source-intrusion evidence. `p2-upstream-sync-ci-30884588165.json` records the
following sync to `15dd7bec` and expands the gate to cover the changed CLI and
managed-host tests. Two sync records prove repeatability but do not, by
themselves, close the combined P6 commercial gate.

`p3-upstream-sync-ci-30897083447.json` records a third conflict-free sync to
`b8fd1952`, after P3 completion. It revalidates the permanent adapter and two
patches against ten new upstream commits, including host/runner recovery,
worktree-isolating repro tooling, and stricter Web TypeScript checks.

`p4-upstream-sync-ci-30932712224.json` records the next conflict-free sync to
`8e17c9ec` after the P4 Secret Broker transport slice. It adds explicit Linux CI
coverage for the upstream Runner/harness zygote, semantic database query names,
allocator and threadpool bounds, and process cancellation. The downstream
managed process policy selects the official direct-`Popen` path and rejects
ambient credential forwarding; local single-user Hosts retain upstream
behavior. This preserves compatibility but does not close deployed P4
containment or failure-domain gates.

`p1-oidc-ci-30887476782.json` records the complete OIDC Authorization Code +
S256 PKCE, replica-independent browser transaction, strict ID Token, JWKS
rotation, explicit same-email conflict, and PostgreSQL RLS acceptance on the
exact implementation revision.

`p1-context-shell-ci-30890178928.json` records server-enumerated logical scope
selection, opaque session-bound 60-second Context Snapshots, two independent
API instances sharing PostgreSQL authority, immediate healthy-control-plane
revocation, Outbox invalidation, strict low-risk read degradation, and
fail-closed login/scope/Mutation/WebSocket/new-Run/sensitive-read behavior.
Together with the OIDC record, it closes P1. P3's durable execution authority
is recorded by `p3-ci-30895599094.json`; the overall release remains `NO-GO`
because P0 and P4-P6 still contain pending gates.

P0's three pending gates now list concrete policy, validator, Runbook, build,
and test evidence. `check_production_baseline` distinguishes complete baseline
content from approvals, measured dashboards, and recovery-drill proof;
`check_image_supply_chain` distinguishes a repeatable unsigned candidate from a
signed immutable production image. Its strict v2 contract binds the exact
protected workflow/OIDC subject, digest subjects, transparency proof, fresh
vulnerability and license admission, immutable registry receipt, one-hour
canary, bounded N-1 rollback, and three distinct approvals; repository escape or
symlink evidence is rejected. Both commands have `--require-ready` modes that
fail until their external evidence is complete. The evidence paths on a pending
gate therefore show implemented controls, not a passed gate.

The P4 records separately close the credential-free Repository/ChangeSet/
Worktree control plane, the physical Git/filesystem Runner adapter, the
isolation/Secret/Preview control-plane contract, and the crash-safe Secret
staging, malicious-egress regression, and Linux cgroup-v2 verifier contract.
The verifier reads exact kernel facts and fails closed, but does not create a
cgroup or prove that a production Runner Pod, container, or microVM is actually
hardened. Deployed mutually authenticated Secret Broker and streaming Preview
tunnels, WebSocket/custom-domain/abuse controls, two independent failure
domains, and N-1 rollback therefore remain pending and the release remains
`NO-GO`.

The generation-bound Preview HTTP adapter is also a separate passed contract
gate. It binds the complete control-plane route and exact official
`RunnerSession`, rejects stale reconnect generations and cross-scope metadata,
streams response chunks, and cancels abandoned requests. The follow-up
Runner-local UDS target gate derives a server-chosen socket below a private
Runner root, pins its filesystem identity, forbids TCP fallback, and passes a
real spawned-process/UDS end-to-end test. Official protocol v1 still buffers
each bounded request body in one frame. At that gate the Runner tunnel resolver was still process-local;
the later Placement slice below replaces the ownership decision but not the
cross-host relay transport. The next passed Supervisor contract starts that
real target from an immutable server-owned specification, publishes it only
after a direct UDS health check, excludes ambient credentials, and revokes then
terminates the entire owned process group on stop, crash, or route expiry. Exact-revision run
`30937413470` verifies all 711 PostgreSQL/Chromium compatibility tests, 56
official zygote/query-context regressions, and the 36/22 Linux security matrix.
This remains a local lifecycle seam: it does not establish external reaping
after the Runner itself crashes, dedicated UID/mount/cgroup isolation,
cross-host mutual authentication and relay deployment, Preview WebSocket
forwarding, custom domains, or abuse controls.

The mTLS Secret Broker adapter is another separate passed contract gate. A real
TLS 1.3 socket handshake binds the Runner to one SPIFFE URI SAN, the request has
no caller-selected Runner identity, the Broker injects the only Vault provider,
and the Runner rechecks the complete credential metadata from its launch grant.
Bounded same-request replay allows one transport retry without a second
authority call. The same exact-revision CI independently passes the real
PostgreSQL forced-RLS and dedicated `saas_secret_broker` role matrix. It does
not yet prove deployed certificate lifecycle, cross-host mTLS-to-PostgreSQL,
multi-replica encrypted replay, production Vault/KMS, memory zeroization, or
failure-domain behavior.

The following certificate-lifecycle slice is intentionally narrower than a
production PKI. External CA tooling retains private keys and signing authority;
the SaaS control plane persists only public leaf fingerprints and lifecycle
metadata. PostgreSQL serializes concurrent activation, enforces one active leaf
per Runner/purpose, makes records append-only, exposes only the exact presented
certificate through forced RLS, and invalidates a leaf on expiry, revocation,
purpose mismatch, or Runner connection-generation change. The Secret Broker
checks this authority before reading or redeeming a request. Exact-revision run
`30942353100` passes 721 PostgreSQL/Chromium compatibility tests, 56 official
zygote/query-context regressions, the 36/22 Linux security matrix, Pyrefly,
P4d migration round trips, the 93-artifact wheel check, patch replay, and the
source-intrusion budget; the contract gate is therefore `passed`. External
issuance, Trust Bundle rollout, deployed cross-host mTLS, expiry/compromise
drills, and multi-replica reconciliation remain production blockers.

The next Placement Router slice removes the process-local ownership decision
without modifying the official `TunnelRegistry` or `RunnerSession`. PostgreSQL
stores one live ownership lease per Runner, bound to the exact Connection
Generation, a monotonic Routing Generation, a hashed owner token, a
server-generated opaque relay subject, and a bounded heartbeat deadline.
Concurrent replicas serialize on the Runner row; reconnect immediately fences
the older generation, stale owner tokens cannot release replacements, and a
bounded `SKIP LOCKED` reconciler expires abandoned ownership. Preview RLS
reveals the current route only for the exact still-active Preview token and
Runner generation. The receiving replica re-resolves ownership before touching
its local official session. Exact-revision run `30948364396` passes 724
PostgreSQL/Chromium compatibility tests, 56 official zygote/query-context
regressions, the 36/22 Linux security matrix, Pyrefly, P4e migration round
trips, the 97-artifact wheel check, patch replay, and the source-intrusion
budget; the contract gate is therefore `passed`. The relay remains an
authenticated transport interface rather than deployed cross-host mTLS or a
production message bus, so this slice cannot close the P4 production aggregate.

The follow-up Preview Relay slice implements that interface as a bounded,
one-request TLS 1.3 transport. Both peers must present a certificate with
exactly one `spiffe://omnigent/preview-gateway/{gateway_instance_id}` URI SAN;
the sender binds the server certificate identity to the durable Placement
owner before writing request bytes, and both sides call an injected certificate
lifecycle authorizer. The wire request contains the opaque Placement identity
and complete Preview route fences but no caller-selected network endpoint. The
receiver re-resolves Placement before touching the local official Runner
session. Response bodies remain streamed with byte, frame, idle-timeout, and
disconnect cancellation bounds. There is deliberately no automatic retry, so
an unknown-result POST/PUT/PATCH/DELETE is never replayed. The gate is now
verified by an immutable exact-revision CI record; even with that contract
record, production service discovery, external CA and Trust Bundle
operations, cross-host deployment, network-partition behavior, and two failure
domains remain separate `NO-GO` requirements. Exact-revision run `30951270461`
passes 734 PostgreSQL/Chromium compatibility tests, 56 official zygote/query
context regressions, the 36/22 Linux security matrix, Pyrefly, P4e migration
round trips, the 99-artifact wheel check, patch replay, and the source-intrusion
budget; the transport contract gate is therefore `passed`. Eleven aggregate
acceptance gates remain pending and the release remains `NO-GO`.

The next p4f candidate persists the previously injected Preview Gateway
directory and Relay certificate authorizer. Gateway IDs are process-lifetime
and never reusable; immutable internal endpoints and provenance are bound to a
hashed registration token, bounded heartbeat lease, monotonic drain/release/
expiry lifecycle, and non-secret Outbox events. Legacy p4e Gateway references
become released tombstones before a foreign key is installed. Placement claim,
heartbeat, Preview route resolution, and Relay certificate authorization all
fail when the Gateway lease is stale.

Relay client and server leaves use separate exact-EKU purposes, one Gateway
SPIFFE URI, exact server-name coverage, accepted Trust Bundle metadata, bounded
rotation overlap, and immediate revocation. Raw tokens, certificate DER, and
private keys never enter PostgreSQL or Outbox. Column grants plus forced RLS
hide token hashes and reveal only live endpoint fields or the exact presented
fingerprint/purpose. Exact-revision run `30955223169` at
`ece5e58120e8a6147174736b89126abfee48e953` passes 745
PostgreSQL/Chromium compatibility tests, 56 official regressions, the 36/22
Linux security matrix, Pyrefly, p4f migration round trips, the 103-artifact
wheel check, both patch replays, and the source-intrusion budget. The subgate
is therefore `passed`; the evidence-successor wheel requires 104 artifacts.
External CA/Trust Bundle operations, deployed cross-host registration and
service discovery, network partitions, and two failure domains remain
independent `NO-GO` requirements. Eleven aggregate gates remain pending.

The p4g implementation adds a downstream-owned Preview Gateway process coordinator
and an explicit non-routable `starting` state. It prepares and installs a
purpose-separated client/server leaf pair without exposing private-key bytes,
binds the Relay listener before durable registration, verifies the exact
advertised mTLS endpoint while the directory still rejects routing, and only
then atomically activates the Gateway. Heartbeats extend a bounded lease;
renewal activates both replacement leaves before installing them; partial
pair activation is revoked; and startup, maintenance, signal, or planned-drain
failure removes readiness, closes the listener, releases or expires the
registration, revokes current leaves, and asks the key provider to destroy the
private material. PostgreSQL rejects activation without both valid purposes,
one common accepted Trust Bundle, direct Gateway-role activation,
activation-time rewrite, lifecycle reversal,
and stale endpoint reuse. Migration `p4g000000001` passed a real PostgreSQL
`p4f -> p4g -> p4f -> p4g` local round trip. Exact implementation run
`30959947571` at `e698027952e171bf3a22e4360373965626f56fd7` passes
753 PostgreSQL/Chromium compatibility tests, 56 official regressions, the
36/22 Linux security matrix, Pyrefly, p4g migration upgrade/check/downgrade,
the 106-artifact wheel check, both patch replays, and the source-intrusion
budget. The runtime subgate is therefore `passed`; the evidence-successor
wheel requires 107 artifacts and eleven aggregate gates remain pending.
The pre-activation readiness interface requires an independently authorized
platform health probe identity rather than the still-disabled Gateway client leaf.
This does not provide an external CA, production Trust Bundle distribution,
deployed DNS/load-balancer registration, cross-host topology, network-partition
evidence, or two failure domains; production remains `NO-GO`.

The p4h slice packages that lifecycle as an executable, unprivileged process
contract. Its strict non-secret JSON configuration rejects symlinks, unsafe file
ownership/modes, unknown or duplicate fields, static Gateway IDs/tokens, non-loopback
health sockets, and invalid timing relationships. Every process start creates a new
opaque Gateway identity and registration token in memory. A trusted deployment-only
factory supplies narrow mTLS control-plane clients, external CA/HSM key handling, the
Relay listener, a separately provisioned platform-health identity, and the persistent
drain observer; the Gateway must never receive a `saas_platform` database credential.

The executable exposes detail-free `/livez` and `/readyz` only on loopback, probes the
advertised listener with TLS 1.3, hostname validation, and an exact server-leaf pin,
and handles SIGTERM/SIGINT during blocked startup without leaving a routable identity.
The wheel includes hardened systemd and Kubernetes templates with non-root/read-only/
no-capability defaults and default-deny networking. The example intentionally remains
single-replica until a deployment renderer assigns each Pod a unique directly routable
endpoint. Exact implementation run `30964370004` at
`742eafd22e82244df89efe7ffc965eb3d5e0bcc0` passes 775 PostgreSQL/Chromium
compatibility tests, 56 official regressions, the 36/22 Linux security matrix,
Pyrefly, p4g migration round trips, the 113-artifact wheel check, both patch replays,
and the source-intrusion budget. The process/deployment contract subgate is therefore
`passed`; the evidence-successor wheel requires 114 artifacts. External CA/HSM,
signed deployed image, DNS/LB, NetworkPolicy allowlists, cross-host partitions, two
failure domains, and N-1 rollback remain separate production blockers. Eleven
aggregate gates remain pending and the release remains `NO-GO`.

The p4i candidate removes the remaining direct-database temptation from the Gateway
factory boundary. `MutualTlsPreviewGatewayControlClient/Server` expose only register,
activate, heartbeat, drain, release, certificate-metadata activation, and
same-Gateway revocation. The server derives one exact process-generated Gateway ID
from a dedicated non-CA ClientAuth URI SAN, invokes an injected per-method workload
authorizer before dispatch, rejects Relay and platform-health identities, prohibits
client-selected authority time, bounds HTTP/JSON framing, disables redirects and
environment proxies, and returns only non-secret receipts. Local real TLS plus real
PostgreSQL 16 tests exercise split `saas_platform`/`saas_preview_gateway` roles and
cross-Gateway revocation denial. Exact implementation run `30967154951` at
`0516d80ca3dc5a1b1a6e8108bf92fc673074be82` passes 781 PostgreSQL/Chromium
compatibility tests, 56 official regressions, the 36/22 Linux security matrix,
Pyrefly, p4g migration round trips, the 115-artifact wheel check, both patch replays,
and the source-intrusion budget. The control transport subgate is therefore `passed`;
the evidence-successor wheel requires 116 artifacts and eleven aggregate gates remain
pending. Production remains `NO-GO`: external workload issuance, CA/HSM, signed
deployment, NetworkPolicy allowlists, cross-host partitions, two failure domains, and
N-1 rollback remain independent requirements.

The first P5 candidate implements a durable outbound Webhook delivery contract without
claiming the P5 production aggregate. Tenant-scoped endpoint metadata stores only Secret
references and rotation versions. Every delivery attempt resolves all A/AAAA answers,
rejects the complete target if any answer is non-public, pins one validated IP for the
TLS connection, verifies the original hostname through SNI, never follows redirects,
and persists only bounded response metadata. Versioned HMAC signatures retain stable
Delivery/Event identities across retries and authorized manual DLQ replay. PostgreSQL
forced RLS separates tenant registration/enqueue from the least-privilege global
`saas_webhook_dispatcher`; `SKIP LOCKED` leases, immutable event facts, a replay guard,
and an Outbox audit record cover replica races and operator actions.

The implementation first ran at `569c1d0352beebee5f069dea8bac1890b4f3304a`.
Compatibility run `30978680709` is deliberately not acceptance evidence: Linux
scheduling exposed an older Preview Gateway runtime mixing its injected authority clock
with wall time during a 300 ms test lease. Commit
`d8f47804b767c6d24bc71694fa9c5e1882abc114` passes that same logical clock to every
directory and certificate lifecycle operation and adds a regression that delays real
time beyond the lease without advancing authority time. Exact run `30980110086` then
passes 795 PostgreSQL/Chromium compatibility tests, 56 official zygote/query-context
regressions, the 36/22 Linux security matrix, Pyrefly with zero errors, p5a migration
upgrade/check/downgrade, the 119-artifact wheel inventory, both patch replays, and the
source-intrusion budget at 8 files/434 lines with a 0.9931 isolated-code ratio. The
signed Webhook/SSRF contract subgate is therefore `passed`; the evidence-successor
wheel requires 121 artifacts and eleven aggregate gates remain pending.

Image candidate run `30978680569` separately repeats Server and Host builds for
`linux/amd64` and `linux/arm64` at exact implementation revision `569c1d03` and schema
`p5a000000001`; both platform manifest/config facts match across attempts. Those OCI
archives are neither registry-published nor signed, vulnerability/license admission
and protected workflow identity are absent, and no canary or N-1 rollback ran. The P0
image gate therefore remains pending. Production DNS policy, egress proxy/firewall
enforcement, external Secret/KMS operation, receiver conformance, capacity/SLO
evidence, deletion workflows, and multi-AZ recovery remain independent P5 `NO-GO`
requirements.

Recovery readiness now has a separately executable contract in
`saas/production/recovery-policy.json` and
`python -m saas.scripts.check_recovery_readiness`. It rejects policy drift,
canonical-record tampering, stale or different-release evidence, shared restore
boundaries, same-failure-domain backup storage, missing signatures/attestations,
incomplete safety checks, and RPO/RTO overruns. An empty evidence directory is a
valid repository state but reports production `blocked`; it cannot be converted to
`ready` without one current, exact-revision production Tenant drill and one cluster
drill. This closes no multi-AZ, PITR, or recovery aggregate gate by itself.

Exact Linux/PostgreSQL 16 run `30983318630` at
`689d364ca809d762cfe1d21232c5f50739cc9be2` passes 801 compatibility tests,
56 official regressions, the 36/22 Linux safety matrix, Pyrefly, migration round trip,
the 124-artifact wheel check, both patch replays, and intrusion enforcement. It closes
only the verifier-contract subgate; its own report records zero production evidence,
zero qualified scopes, and two readiness blockers.

The compatibility workflow also executes
`python -m saas.scripts.run_postgresql_restore_contract` against PostgreSQL 16. It
uses two disposable database names, a custom-format `pg_dump`/`pg_restore`, the exact
official/SaaS migrations, canonical 50/17 forced-RLS inventories, post-backup
revocation/deletion-marker replay, cross-scope negative probes, and selected-table
content hashes. The databases and archive are destroyed after the report. Its
evidence kind is permanently `ci_contract_not_production_drill`; passing it does not
claim PITR, WAL continuity, multi-AZ, a second failure domain, or production recovery.

Exact run `30986200469` at
`470105a68a9992ba12258c3be96b600ca4e0ae28` passes 809 compatibility tests,
56 official regressions, the 36/22 Linux safety matrix, Pyrefly, migration round trip,
the 128-artifact wheel, both patch replays, and the 8-file/443-line intrusion result.
Its PostgreSQL 16 restore report completes in 2.961 seconds with matching hashes,
50/17 forced-RLS inventories, both cross-scope probes, and post-backup revocation and
deletion-marker replay. It closes only the CI logical-restore contract subgate;
eleven production gates and the release-level `NO-GO` are unchanged.

Tenant deletion has an independent machine-readable contract in
`saas/production/deletion-policy.json` and
`python -m saas.scripts.check_deletion_readiness`. It enforces a complete thirteen-
surface manifest, exact revisions, trusted preconditions, zero/cryptographic erasure,
bounded redacted/anonymized retention, backup tombstones and purge dates, the full
cross-store reconciliation matrix, immutable signed evidence, and independent privacy,
security, and data-owner attestations. The empty production evidence directory is
deliberate: structural validation reports `pass`, production reports `blocked`, and no
aggregate deletion or production-foundation gate is closed by the validator alone.

Exact run `30988807799` at
`cd681559684377a5d5b0a25c23c23749eeb85d48` passes 817 compatibility tests,
56 official regressions, the 36/22 Linux safety matrix, Pyrefly, migration round trip,
the 133-artifact wheel, both patch replays, and the 8-file/446-line intrusion result.
The deletion validator itself reports thirteen required surfaces, zero production
records, zero qualified records, and one readiness blocker. It closes only the
fail-closed verifier-contract subgate; eleven production gates and the release-level
`NO-GO` remain unchanged.

SLO and capacity readiness has an independent machine-readable contract in
`saas/production/slo-capacity-policy.json` and
`python -m saas.scripts.check_slo_capacity_readiness`. It requires active production
dashboards for all six baseline SLOs, a complete 30-day observation in two failure
domains, bounded error-budget burn, all seven services under five load and failure
scenarios, ten resource-dimension checks, six on-call alert drills, immutable signed
artifacts, and three independent attestations at the exact release revision. Strict
schemas reject raw Tenant fields, CI evidence kinds, incomplete catalogs, tampered
records, stale observations, and policy drift. The repository deliberately contains
no production record and retains six `planned` dashboards, so the structural check
passes while production readiness reports seven blockers. Passing the verifier's CI
contract does not close the actual SLO, capacity, multi-AZ, or aggregate P5 gate.

Exact run `30991532016` at
`05fbe7d80d32e5337f515a389520c1813d2a469f` passes 827 compatibility tests,
56 official regressions, the 36/22 Linux safety matrix, the 2.82-second logical
restore contract, Pyrefly, migration round trip, the 138-artifact wheel, both patch
replays, and the 8-file/449-line intrusion result. Its SLO/capacity report remains
deliberately blocked with six inactive dashboards and no qualifying production
record. It closes only `p5-production-slo-capacity-evidence-verifier-contract`;
eleven aggregate gates and the release-level `NO-GO` remain unchanged.

Image supply-chain readiness now uses the strict v2 policy and
`python -m saas.scripts.check_image_supply_chain`. It pins the approved repository
paths, Server/Host targets, dual-architecture smoke matrix, labels, locks, regression
suites, exact main-workflow/OIDC/builder/environment identity, SBOM and provenance
subjects, signature subject and transparency metadata, fresh zero-Critical/High
vulnerability result, and zero-denied/unknown license policy. Admission must precede
the one-hour SLO/security canary; a different verified N-1 digest must then roll back
within 900 seconds before three distinct roles attest. Strict schemas and the safe
loader reject weakening, unknown fields, type substitution, stale or reordered facts,
canonical-record tampering, absolute/escaping paths, symlinks, and non-object JSON.

Exact run `30994862629` at
`0200b00a116bffbf3c722d82fe05c3735f69014a` passes 836 compatibility tests,
56 official regressions, the 36/22 Linux safety matrix, a 2.784-second logical restore,
Pyrefly, migration round trip, the 139-artifact wheel, both patch replays, and the
8-file/449-line/0.9935 intrusion result. The report records two policy images, zero
production evidence images, zero promotions, and one blocker. It closes only
`p5-image-supply-chain-evidence-verifier-contract`; external registry, signature,
scan/SBOM/provenance artifacts, protected workflow execution, canary, rollback, and
approvals remain unproven. The evidence-successor wheel requires 140 artifacts;
eleven aggregate gates and the release-level `NO-GO` remain unchanged.

P6 is now `in_progress` at the implementation level through a first
machine-identity/API contract slice. Downstream-owned Service Accounts have an
explicit active human Steward, project scope, a monotonic security version, and
no implicit creator membership or permission inheritance. API Keys are shown
once, stored only as HMAC-SHA256 digests with an independently injected pepper,
and bind exact delegated permissions, canonical network CIDRs, expiry, and
account security version. Creation, rotation, revocation, Steward transfer, and
suspension are idempotent, transactional, and publish secret-free Outbox facts;
member removal is blocked until explicit Steward transfer.

The optional `/api/v1` router separates machine Bearer authentication from the
existing `/saas` Cookie surface, rejects Cookie/Bearer ambiguity, and never
authorizes Service Accounts on upstream Runtime routes. The `p6a000000001`
migration expands the control-plane forced-RLS inventory to 52 tables and limits
the authenticator to an exact server-derived `app.api_credential_id` plus
coalesced last-use fields. Backup/restore and deletion contracts now include
machine-credential revocation.

Exact run `31002035206` at
`f5b6d06d16903943028ce0b8f6adf9534e05d3c2` passes 843 compatibility tests,
57 official Zygote/query-context regressions, the 36/22 Linux safety matrix,
Pyrefly with zero errors, p6 migration round trip, the 145-artifact wheel, both
patch replays, and the 8-file/449-line/0.9938 intrusion result. Its PostgreSQL 16
restore takes 2.924 seconds with 52/17 forced-RLS inventories, two Service Account
rows, two API Key rows, cross-scope denials, and post-backup machine-credential
revocation replay. It closes only
`p6-service-account-api-credential-contract`; the evidence-successor wheel requires
146 artifacts. Billing, enterprise federation, complete audit/API/console/privacy
capability, commercial evidence, all eleven aggregate gates, and the release-level
`NO-GO` remain pending.

The second P6 contract slice adds Tenant groups and Project custom roles without
granting permissions from group membership alone. Custom roles are compiled only
from canonical Project permissions; Critical, cross-scope, `grant.manage`, and
`custom_role.manage` delegation are rejected, and the delegator must hold every
permission being delegated. Group membership and role-assignment expiry fail closed,
and the authorization explanation records the exact group, role ID, and role version.

Cookie Admin routes retain Origin/CSRF enforcement and action-level permission
registration. Their opaque UUID cursors use bounded keyset queries rather than
loading a Tenant's full collection. Mutations are Tenant-idempotent and emit
secret-free Outbox facts. Direct group member removal revokes live sessions and
increments both user security and affected Project authorization versions; Tenant
member-removal preflight includes group and assignment facts, rejects snapshot drift,
and revokes group access atomically. Space-only removal leaves Tenant-wide group
membership intact.

Exact run `31008792059` at
`85e4399de928bc7cffb76dbe763f9a2e3b1641a6` passes 852 compatibility tests,
57 official Zygote/query-context regressions, the 36/22 Linux safety matrix,
Pyrefly with zero errors, `p6a000000002` migration round trip, the 150-artifact
wheel, both patch replays, and the 8-file/449-line/0.9941 intrusion result. Its
PostgreSQL 16 restore takes 2.954 seconds with 56/17 forced-RLS inventories and
two rows in each of the four enterprise tables. It closes only
`p6-enterprise-group-project-custom-role-contract`; the evidence-successor wheel
requires 151 artifacts. Group archival/role retirement/bulk directory lifecycle,
federation/SCIM, complete audit/API/console/privacy capability, billing, commercial
evidence, all eleven aggregate gates, and release `NO-GO` remain pending.

The third P6 contract slice adds terminal Group Archive, Project custom-role
retirement, and 1--100 item atomic membership batches. Cookie Admin routes retain
Origin/CSRF and action-level authorization; every transition requires an expected
version, reason, and Tenant-scoped idempotency key. Archive and retirement revoke
their dependent grants in the same transaction, invalidate affected user sessions
and authorization caches, and emit secret-free Outbox facts. A Tenant-scoped
PostgreSQL transaction advisory lock prevents cross-resource enterprise-write
deadlocks without serializing different Tenants.

Migration `p6a000000003` preserves truthful legacy provenance with an explicit
backfill marker and restores FORCE RLS before its PostgreSQL transaction commits.
Backup/restore now replays post-backup Archive and Retire transitions. Exact run
`31016011969` at `7578d2d1bcbfae260142bad166a1851ce4168dfa` passes 856
compatibility tests, 57 official regressions, the 36/22 Linux security matrix,
Pyrefly with zero errors, the migration round trip, both patch replays, and the
153-artifact implementation wheel. Its PostgreSQL 16 logical restore takes 3.086
seconds with 56/17 forced-RLS inventories and enterprise-lifecycle replay. The
8-file/449-line/two-patch/0.9942 intrusion result remains within budget. This closes
only `p6-enterprise-access-lifecycle-contract`; the evidence-successor wheel requires
155 artifacts. Dedicated pre-execution impact approval UI, directory sync/SCIM,
federation, billing, complete audit/API/console/privacy capability, production proof,
all eleven aggregate gates, and release `NO-GO` remain pending.

The fourth P6 contract slice advances the downstream head to `p6a000000004`
and makes Cookie Admin Group Archive/custom-role Retire require a persisted,
15-minute impact snapshot plus a different-principal approval. The snapshot binds
the requester, target/version/reason and exact affected membership, assignment,
session/security and Project-authorization facts. Approval and execution re-evaluate
permissions and the hash; fresh-auth expiry, self approval, stale impact, approver
permission loss, cross-scope reuse and concurrent decision losers fail closed.

Exact run `31025362985` at
`7f3350ffad677e7249ef5eda6ad4fb738e617503` passes 859 compatibility tests,
57 official regressions, the 36/22 Linux security matrix, Pyrefly with zero errors,
the `p6a000000004` migration round trip, both patch replays, and the 157-artifact
implementation wheel. Its PostgreSQL 16 restore takes 2.948 seconds with 57/17
FORCE-RLS inventories, preserves two preflight rows, and replays one approved record
to `executed`. The 8-file/449-line/two-patch/0.9944 intrusion result stays within
budget. This closes only `p6-enterprise-access-impact-approval-contract`; the
evidence-successor wheel requires 158 artifacts. The production approval inbox and
confirmation UI, directory federation, commercial proof, all eleven aggregate gates
and release `NO-GO` remain open.

The fifth P6 slice productizes the approval boundary inside the existing
`/saas/admin/projects` control plane. Bounded requester, Tenant Group decision, and
selected-Project custom-role decision queues use opaque UUID keyset pagination,
exclude the requester and expired pending records, and expose only server-derived
target labels and impact counts. Full impact snapshots remain server-only. The
Approval Desk requires reasons for prepare, approve, reject, and execute; only a
different authorized principal may decide, and only the original requester may
execute an approval.

Exact run `31030826038` at
`67d53a11c54f1fa0715f000f3f18a13b12366d12` passes 861 compatibility tests,
57 official regressions, the 36/22 Linux security matrix, Pyrefly with zero errors,
the `p6a000000005` migration round trip, both patch replays, and the 159-artifact
implementation wheel. Its PostgreSQL 16 restore takes 2.916 seconds with 57/17
forced-RLS inventories and approval replay. A two-principal Chromium chain proves
approve, reject, requester-only execute, Archive/Retire terminal state, and zero
browser console errors. Run `31030351743` first failed closed because the real
PostgreSQL assertion had not yet admitted both same-Tenant Group and role preflights;
the successful revision corrected that assertion without weakening the cross-Tenant
denial. The intrusion result remains 8 files, 449 lines, two patches, and 0.9945
isolated custom code.

That exact-revision evidence is attached to the still-pending
`p6-enterprise-identity-audit-api-platform-console-privacy` aggregate gate. It does
not turn official server-level `/settings/members` into Tenant administration, nor
does it complete a Tenant Members module for invitation, Tenant/Space roles,
suspension/removal, identity connections, Owner transfer, and impact preflight. The
evidence-successor wheel requires 160 artifacts; eleven aggregate gates and release
`NO-GO` remain unchanged.

The first evidence-successor run `31031605442` correctly failed on a browser ordering
race: its initial empty Group GET could resolve after the post-create refresh and
overwrite the newer render. The corrective implementation does not mask the race with
a longer timeout or a rerun. It gives Group, custom-role, and approval reads monotonic
revisions, invalidates them on logout, and binds the approval result to the captured
actor, Tenant, Space, and selected Project. A deterministic Chromium probe delays a
completed empty response until after create and verifies that it cannot replace the
new state.

Exact run `31032344986` at
`1382f2032c9f804e3ce702af03b0c3953e13fe9d` passes 861 compatibility tests in
124.91 seconds, a 7.982-second PostgreSQL 16 logical restore, 57 official tests in
29.62 seconds, the 36/22 Linux matrix in 12.73 seconds, Pyrefly, the
`p6a000000005` round trip, both patch replays, and the 160-artifact wheel. The
8-file/449-line/two-patch/0.9945 intrusion result is unchanged. Its evidence-successor
wheel requires 161 artifacts. This remains evidence under the pending enterprise
console aggregate; at that revision Tenant user management was still incomplete and
`NO-GO` was unchanged.

The next P6 slice productizes Tenant user administration as `Tenant Members` inside
the same `/saas/admin/projects` control plane. It adds privacy-bounded member search,
status filtering, login-method summaries, Tenant and all-Space memberships, CAS role
and suspend/resume actions, invitation create/list/reissue/revoke/accept, Owner
transfer, and server-snapshot-bound member removal. One-time invitation tokens are
returned only in `no-store` responses and never enter Outbox payloads. Every Cookie
mutation rebinds actor/Tenant/Space, checks Origin and CSRF, reauthorizes the action,
and requires reason, expected version, and idempotency. Admin elevation requires the
current Owner plus fresh authentication. `saas_authenticator` and `saas_governance`
remain separate least-privilege lifecycles, and `p6a000000007` lets the authenticator
see only an exact invitation token hash under forced RLS.

Runs `31041546256` and `31041546082` correctly failed closed when Chromium exposed a
real governance race: the Space Role action could outrun the preceding Tenant Role
refresh. The correction locks the entire selected-member surface until the server
mutation and member reload finish, and browser assertions wait for server-confirmed
Tenant/Space version advances. It was validated locally in five consecutive delayed-
read Chromium runs and remotely without rerun or timeout inflation.

Exact run `31042515162` at
`17e3f6b4d3156ee22049fb6aaaac306be25d3cf4` passes 865 compatibility tests in
154.34 seconds, a 3.498-second PostgreSQL 16 logical restore with 57/17 forced-RLS
inventories, 57 official tests in 39.48 seconds, the 36/22 Linux matrix in 17.19
seconds, Pyrefly with zero errors, the `p6a000000007` migration round trip, both
patch replays, and the 166-artifact implementation wheel. The intrusion result is
8 files, 449 lines, two patches, and 0.9947 isolated custom code. Its evidence-
successor wheel requires 167 artifacts. This closes the Tenant Members product
slice, not SCIM/directory sync, enterprise federation, bulk/delegated lifecycle,
billing, full audit/API/privacy, production recovery, the pending P6 aggregate, any
of the eleven aggregate gates, or release `NO-GO`.

The evidence successor `04bb33a1` passes exact run `31043445834` with the same
865/57/36+22 matrix, a 3.049-second restore, Pyrefly, `p6a000000007`, two patches,
the 167-artifact wheel, and the unchanged intrusion result. Manually dispatched
image run `31043457794` then tests 864 cases with one platform skip and builds the
Server and Host targets twice for both `linux/amd64` and `linux/arm64`. All four
platform Manifest/Config pairs match across repeated builds, and every image labels
the exact product revision `04bb33a1`, upstream `8c191ac0`, schema
`p6a000000007`, and adapter `0.2.0`. The image-evidence successor wheel requires
168 artifacts. These are unpublished candidate archives, not signed, scanned,
registry-pinned, canaried, or N-1-rollback production images; P0 and P6 remain
pending and release remains `NO-GO`.

The official baseline was first advanced from `559504d9` to `d794ef4f` through
eleven commits and 27 changed files with zero merge conflicts. Exact sync run
`31011047850` verifies that first current P6-era sync. A second strictly later
official advance to `8c191ac0` then merged two commits and five files without a
conflict. Run `31018890417` correctly failed because several current Runtime and
production-policy Revision Contracts still named the prior baseline; they were
advanced together rather than weakening the checks.

Exact corrected run `31019511803` at
`6121663028d8d5501b1a41f284146ec8ce3b4e40` passes 856 compatibility tests,
57 official regressions, the 36/22 Linux security matrix, Pyrefly, the
`p6a000000003` round trip, both patch replays, the 155-artifact wheel, and a
2.923-second PostgreSQL restore. Both exact runs stay within the 8-file/449-line/
two-patch intrusion budget, satisfying the two-consecutive-sync condition. The
combined `p6-two-consecutive-upstream-syncs-and-commercial-gate` remains pending
because pricing, billing reconciliation, customer acceptance, and other commercial
evidence are absent. The evidence-successor wheel requires 156 artifacts, and the
release remains `NO-GO`.

The seventh P6 contract slice introduces ten Tenant billing tables at migration
`p6a000000008`: Subscription, immutable versioned Pricing, scoped Entitlement,
immutable Usage, a rebuildable Balance projection, Reservation, append-only Customer
and Provider ledgers, and immutable Reconciliation batches with one-way mismatch
resolution. Money uses integer minor units and quantities use bounded Decimal values;
database checks enforce conservation and PostgreSQL triggers reject fact mutation.
Pricing-window creation is serialized per Tenant, and the Balance projection is
auditable and version-rebuildable only from immutable ledger deltas.

The dedicated `saas_billing` role has no content, Secret, credential, Run, or Project
access. The existing `/saas/admin/projects` page gains a content-blind Billing module;
its Cookie routes expose configuration and inspection but deliberately provide no
Credit, Reserve, Usage, Settlement, Refund, or Provider-cost ingestion endpoint.
Exact run `31055362434` at
`7f985c1c1aebdff5370500a7175ce151f9a5d5bb` passes 877 compatibility tests in
167.78 seconds, a 3.814-second PostgreSQL 16 logical restore with nonempty rows in all
ten billing tables and 67/17 forced-RLS inventories, 57 official tests in 41.58
seconds, the 36/22 Linux matrix in 17.83 seconds, Pyrefly, migration round trip, both
patch replays, and the 173-artifact implementation wheel. The intrusion result remains
8 files, 449 lines, two patches, and 0.9951 isolated custom code. The evidence-successor
wheel requires 174 artifacts.

This evidence is attached to the still-pending
`p6-billing-ledger-entitlement-quota-subscription` aggregate gate. Non-human metering
identity, authenticated internal ingestion, real Run/Provider integration, period
rollover, signed and ordered Provider webhooks, real invoices, payment/tax boundaries,
production operations, commercial acceptance, all eleven aggregate gates, and release
`NO-GO` remain open.

The successor `p6a000000009` machine-metering slice adds a dedicated `saas_metering`
role, execution-bound metering authority, immutable receipt, and TLS 1.3 mutual-auth
transport. The server derives Tenant/Space/Project/actor/session/Pricing from a current
Runner certificate, exact capability, Dispatch generation, Run lease and fence; caller
scope and price are invalid request fields. The transport requires one canonical Runner
SPIFFE URI SAN, checks the durable `billing_metering` certificate lifecycle, derives the
certificate fingerprint from DER, bounds and strictly parses one HTTP/1.1 endpoint, and
does not hide retries.

The PostgreSQL restore fixture now contains two nonempty machine receipts and every
linked Usage/Run/Capability/certificate/Runner authority row. It proves receipt
cross-Tenant denial for `saas_billing`, link integrity, the restored immutable trigger,
and 68/17 forced-RLS inventories. Local evidence passes 23 focused metering, billing,
migration, and restore tests, the complete 889-test compatibility matrix on a clean
PostgreSQL 16 database in 339.37 seconds, a 28.408-second isolated logical restore, the
177-artifact implementation wheel, and full Pyrefly with zero errors. The full matrix
also exposed and closed a Project Admin readiness race: scope submission remains disabled
until discovery finishes, and a deterministic Chromium test delays the scope response by
750 milliseconds before proving no early submission is possible.

Exact compatibility run `31063360786` at
`b2285a70b0c78131b043200c4b1cc1ca8536877f` passes 889 tests in 144.76 seconds,
a 3.134-second PostgreSQL 16 logical restore with two linked machine receipts and 68/17
forced-RLS inventories, 57 official tests in 34.33 seconds, the 36/22 Linux security
matrix in 15.14 seconds, Pyrefly, migration round trip, both patch replays, and the
177-artifact implementation wheel. The intrusion result remains 8 files, 449 lines,
two patches, and 0.9953 isolated custom code. The evidence-successor wheel requires
178 artifacts.

Image candidate run `31063360725` is deliberately excluded from machine-metering
acceptance because all four repeated builds still supplied the stale
`p6a000000007` schema label. The evidence successor instead derives the only migration
head from `saas/production/baseline.json`, passes it to every Server/Host build, and
adds a fail-closed workflow-source check. Corrected image run `31064837882` at
`f75be5a62813b00740334ba701be9633b1dab9e3` passes 888 tests with one platform skip,
migration round trip, both patches, and the 8-file/451-line/0.9953 intrusion result.
Server and Host each build twice for both supported architectures with matching
Manifest/Config pairs, the exact `p6a000000009` label, and two attestation descriptors
per build. This is accepted candidate evidence, not a published, signed,
vulnerability-cleared, canaried, or rollback-proven production image. The
evidence-successor wheel requires 179 artifacts.

The downstream Runtime Partition now wires official usage completion to the machine
client through three generic upstream seams: Host construction, Runner entry-module
selection, and a required fail-closed usage sink. Managed launch uses a scheduler-staged
one-time grant and a mode-0600 envelope that is unlinked before official Runner startup;
input/output usage is atomically spooled without Prompt/output/capability content and
retried over TLS 1.3 mTLS with stable idempotency. Local tests cover official Client and
Host launch paths, failure and restart replay, strict spool rejection, and one complete
official Provider observer -> mTLS -> durable certificate -> real PostgreSQL
`saas_metering` RLS -> immutable receipt path. The implementation wheel requires 181
artifacts. Exact compatibility run `31068082417` at
`0e886d503b4fbd12813de3a6034f451e6e3e4e8a` passes 901 tests in 149.00 seconds,
a 6.672-second PostgreSQL 16 logical restore with two linked machine receipts and 68/17
forced-RLS inventories, 57 official tests in 29.88 seconds, the 36/22 Linux security
matrix in 12.76 seconds, Pyrefly, migration round trip, two patch replays, and the
181-artifact implementation wheel. Source intrusion remains within budget at 9 files,
479 lines, two patches, and a 0.995 isolated ratio. The evidence-successor wheel
requires 182 artifacts.

This does not yet establish production billing. The durable scheduler-to-Host raw-grant
handoff is not deployed, the official observer exposes no Provider-native request ID,
and a kill between Provider completion and notification remains a reconciliation window.
Period rollover, signed/ordered/replay-safe Provider webhooks, real Provider invoice
comparison, payment/tax boundaries, production operations, commercial acceptance, all
aggregate gates, and release `NO-GO` remain open.

PC1 establishes the separate Platform Staff security realm without turning the customer
Tenant Admin or PostgreSQL emergency role into a super-admin product. Migration
`pc1a00000001` adds Staff principals, role assignments, phishing-resistant sessions, and
content-blind Tenant/User projections. The standalone API uses an independent HTTPS
Origin, `__Host-` Cookie, Audience and CSRF contract; 22 Platform permissions, five
built-in least-privilege roles, field-level metadata and explicit no-content defaults have
no `allow_all` path. Independent application, authenticator, governance and projector
roles cannot inherit or `SET ROLE` the emergency `saas_platform` authority.

Initial run `31184944950` correctly failed closed because sync Playwright on pytest's main
thread left an active event loop and rejected 38 later asynchronous Preview tests. The
fix runs both Platform and Tenant Admin Chromium scenarios in dedicated Playwright
threads and removes an absolute one-hour test-session expiry. Exact successor run
`31187073403` at `07b368033d91aa4fe4d3e649b4c3dccd358f3e0e` passes 934 tests in
145.80 seconds, a 3.173-second PostgreSQL 16 logical restore with 73/17 forced-RLS
inventories and nonempty PC1 facts, 57 official tests in 30.68 seconds, the 36/22 Linux
security matrix in 14.10 seconds, Pyrefly with zero errors, the migration round trip,
both patch replays, and the 187-artifact implementation wheel. Source intrusion remains
within budget at 9 files, 479 lines, two patches, and a 0.9952 isolated-code ratio.

This closes the PC1 code and CI slice only. It does not prove a deployed enterprise Staff
IdP or Platform Origin, PC2 global User/Tenant lifecycle, PC3 governed support and
immutable evidence, PC4 Platform Console UI, PC5 enterprise operations, any of the eleven
aggregate production gates, or release `GO`.

Manually dispatched image run `31187141816` verifies the same exact implementation SHA
with 933 tests and one platform skip, then builds Server and Host twice for both
`linux/amd64` and `linux/arm64`. Every repeated platform Manifest and Config digest
matches, has two attestation descriptors, and labels exact product `07b36803`, upstream
`63035f92`, schema `pc1a00000001`, and adapter `0.2.0`. These are unpublished candidate
archives, not registry-pinned, signed, vulnerability/license-cleared, canaried, or
N-1-rollback production images; P0 remains pending and release remains `NO-GO`. The two
PC1 machine records bring the evidence-successor wheel requirement to 189 artifacts.

PC2/P6 implementation commit `2d92d02fa02b1e418967c91d67e3eccc59659540`
adds target-bound Global User/Tenant lifecycle governance and immutable billing
period-close/Entitlement-rollover facts on migration head `p6b000000001`. Initial
compatibility run `31199941325` correctly failed closed on four PostgreSQL defects:
ordinary roles could not evaluate the Platform assignment predicate, target Auth rows
were not selectable before update, the policy version exceeded its database width, and
immutable Reconciliation facts were locked with an UPDATE-requiring clause. The
successor grants only predicate columns while the Assignment table's own FORCE RLS
returns zero ordinary rows, adds exact-target SELECT policies, shortens the version,
and relies on the per-period transaction advisory lock plus unique close invariant.

Exact compatibility run `31201598950` passes 943 tests in 161.25 seconds, a
3.641-second PostgreSQL 16 isolated logical restore with 75/17 forced-RLS inventories,
57 official tests in 33.80 seconds, the 36/22 Linux security matrix in 15.40 seconds,
Pyrefly with zero errors, migration round trip with no drift, both patch replays, and
the 192-artifact implementation wheel. Source intrusion remains within budget at nine
files, 479 lines, two patches, and a 0.9953 isolated-code ratio. The restore report has
zero `saas_billing_period_closes` rows: schema, RLS and adjacent Billing replay pass, but
nonempty close-fact backup/restore remains an explicit P6 evidence gap.

Image candidate run `31202057865` verifies the same exact SHA with 942 tests and one
platform skip. Server and Host each build twice for both `linux/amd64` and
`linux/arm64`; all repeated platform Manifest/Config pairs match, bind product
`2d92d02f`, upstream `63035f92`, schema `p6b000000001` and adapter `0.2.0`, and contain
two attestation descriptors per build. These archives are not registry-published,
signed, vulnerability/license-cleared, canaried, or rollback-proven production images.
The two PC2/P6 machine records bring the evidence-successor wheel requirement to 194
artifacts.

This accepts only the first PC2 and P6 code/CI/image-candidate slices. Identity Conflict
Case governance, destructive User/Tenant deletion manifests, Provider-native Receipt
and kill-window recovery, signed Provider webhooks, payment/invoice/tax, PC3, PC4 and
PC5 remain open. All eleven aggregate production gates and release `NO-GO` are
unchanged.
