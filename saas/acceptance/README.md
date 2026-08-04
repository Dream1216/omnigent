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
real spawned-process/UDS end-to-end test. The Runner tunnel resolver remains
process-local, and official protocol v1 still buffers each bounded request body
in one frame. The next passed Supervisor contract starts that real target from
an immutable server-owned specification, publishes it only after a direct UDS
health check, excludes ambient credentials, and revokes then terminates the
entire owned process group on stop, crash, or route expiry. Exact-revision run
`30937413470` verifies all 711 PostgreSQL/Chromium compatibility tests, 56
official zygote/query-context regressions, and the 36/22 Linux security matrix.
This remains a local lifecycle seam: it does not establish external reaping
after the Runner itself crashes, dedicated UID/mount/cgroup isolation,
cross-host mutual authentication and certificate lifecycle, multi-replica
Placement reconciliation, Preview WebSocket forwarding, custom domains, or
abuse controls.

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
