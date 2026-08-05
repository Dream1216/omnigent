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
signed immutable production image. Both commands have `--require-ready` modes
that fail until their external evidence is complete. The evidence paths on a
pending gate therefore show implemented controls, not a passed gate.

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
