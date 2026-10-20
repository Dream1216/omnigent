# Omnigent 0.19 SaaS adoption boundary

The source baseline is `v0.19.0.dev20261020`, commit
`3db749d784ff044304473939acaae3a65c0fec61`. The initial rollout retains
adapter contract `0.2.0`, Runner Session initialization protocol `2`, official
core schema head `nf12ab34cd56`, and control-plane head `p0s000000016`.
The upstream adds the host-session index used for managed startup recovery;
the entire official migration tree is preserved. The SaaS head
adds a reversible authority correction and still requires old-data, RLS, restore
and N-1 tests.

## Initial production capability boundary

| Capability | Initial behavior | Opening condition |
| --- | --- | --- |
| Existing builtin/session Agents, Session create/fork and multi-Agent execution | Use the upgraded upstream with SaaS tenant context, Agent readiness and credential controls | Exact-version tests and paired Server/Host/Runner rollout |
| Standalone user Agent installation and management | `agent_install=false`; the upstream user-agent routes reject through the store capability | Safe N-1 authorization for unbound user-agent rows, then a separate activation change |
| Managed MCP Registry/Gateway | No production registry is composed | Compatible execution Host/Runner, credential/actor binding and multi-replica coordination evidence |
| Public Edit sharing | Maximum effective public level is explicitly `read` | Separate authorization and isolation validation |

`build_production_server` fixes these initial settings. Standalone Agent
installation is disabled through the existing `supports_user_agents` store
capability, leaving ordinary server/session Agent operations delegated to the
same store. The capability also keeps the new settings UI unavailable.

The N-1 signed product `f4404d47f705c7a3c0745c38ccd1a9be125c31ad`
authorizes a session Agent using its associated session. It does not have
0.19's owner check for a user Agent with no associated session. Such rows must
not be introduced through the new installation API before that rollback path
is addressed. Numeric Agent kind values remain `1` and `2`; no historical
migration is rewritten.

## Compatibility changes

- Preview Owner callbacks accept the new `(runner_id, RunnerSession)`
  signature while preserving reservation/token/generation checks. The real
  WebSocket regression covers redemption and release, alongside stale-generation
  and cross-replica one-use registration tests.
- The Host factory seam is forwarded through upstream's new
  `_serve_host_until_exit` helper. Ordinary heartbeat persistence stays separate
  from the ping worker; machine-credential revocation remains fail closed.
- The Preview Runner's private dispatcher and hello pins are refreshed after
  reviewing the optional diagnostics parameter and new MCP advertisement.
  The Preview-only ASGI tunnel removes that unsupported MCP capability from
  hello; TLS, DNS/CIDR binding and one-use registrations remain enforced.
- Nine patches replay against the pinned 0.19 tree and reproduce all 27
  downstream-modified official Python files. No budget or release policy is
  relaxed by the baseline change.
- ServerInfo and Session APIs retain the SaaS authentication, CSRF/Origin and
  RuntimeContext middleware. New routes still require the full isolation matrix.
- SaaS image builds enable `VITE_OMNIGENT_HOST_ROUTING=true`. Multi-replica
  deployments set `OMNIGENT_SAAS_HOST_SHARDED=true` on the Server and
  `OMNIGENT_HOST_SLICE_KEY_ENABLED=1` on executing
  Hosts and consistent hashing of the existing slice header/query onto the
  same Server endpoints. Shared PostgreSQL does not share live tunnels.
  Endpoint updates must drain ingress workers so the Host and browser reconnect
  to the same destination. The upstream unauthenticated prototype alone does
  not satisfy the SaaS rollout gate.
- `OMNIGENT_SAAS_HOST_SHARDED` accepts only `true` or `false`, defaults to
  `false` for a single replica, and is reported by `/saas/version`. The
  two-replica template explicitly enables it. It controls wrong-replica
  recovery, never authorization or placement authority.
- SaaS Account settings read the caller's password version from `/saas/auth/me`
  and use the existing versioned `/saas/password` mutation with CSRF and an
  idempotency key. Successful rotation revokes all sessions, clears local
  authenticated state and requires sign-in again. Accounts without a local
  credential and older servers without the metadata keep this action hidden.
- The ADR candidate is refreshed with `review_required` intact. Historical
  approvals and evidence remain immutable and do not approve this release.

## Bound Public API login migration

`p0s000000016` corrects a pre-existing mismatch between dedicated service logins
and the Public API base-role name. The service requires the exact login from the
immutable role-binding manifest, inherited Public API authority, no privileged
role flags, and no other base-role grants. It does not switch database roles.

The migration alters only the Public API authority predicate in 26 existing
policies. Credential ID, account, Tenant, Space and Project predicates, policy
identity/targets/command/permissiveness, and FORCE RLS remain intact. Previous
migration files and P0S15 source anchors are retained. Clean PG16/18 replays cover
Core, model, platform-admin and Preview profiles; predecessor captures must first
match the existing P0S15 anchors before P0S16 digests are recorded.

Downgrade restores the original policy expressions without rewriting business
rows. This does not by itself admit the original signed 0.18 image against P0S16:
its schema tuple and startup checks must be exercised. A rollback that requires
P0S15 must drain writes, apply the reviewed downgrade and refresh the actual
release-bound receipts before restoring the pinned N-1 components. The complete
recovery must meet the existing 900-second gate. No automatic rollback claim is
made from migration reversibility alone.

## Release requirements

Run the protected SaaS upstream and N-1 workflows, the official affected suites,
Agent and authenticated online gates, PG18/PG16 and restore contracts, and image
supply-chain checks. Promote digest-pinned Server/Host/Runner components together
after mixed-version and draining behavior is proven. Complete the policy-defined
canary and N-1 rollback drill before final production admission. The initial
capability boundary is not a substitute for those gates.

## Trusted main review

The candidate refreshes exact dependency and test-input hashes in the N-1
allowlist while retaining protected-main hashes and the evaluator's required
assertions and acceptance logic. The final commit's review packet must list
all changed automation and every trusted input not accepted by protected main.
Earlier scope-specific approvals do not automatically approve later changes.
The trusted main evaluator
requires explicit administrator review for policy and automation changes and
will reject this candidate until that review is resolved. A candidate-side
green test does not authorize that merge or any production promotion.

## Reviewed source budget

The requester approved the direct-file ceiling from 150 to 152 for the
reviewed frontend contracts and five maintained Linux baselines, then from
152 to 153 for the upstream terminal reconnect test correction. The latter
ignores complete terminal RGB response frames in the typed-input observation
and keeps injected relay closes on the active transport using the existing
loopback-blocking setup. Both terminal surfaces, both close codes, direct
attachment and relay fallback passed six real browser cases without retries.
All reconnect, input and fallback assertions remain enforced. Product code
is unchanged. The 4,576-line ceiling, nine patches, 0.85 isolation floor,
forbidden paths, reverse dependencies and release gates remain enforced.

Subsequent individually approved increases set the direct-file ceiling to 156.
The latest increase covers the upstream MCP Registry compatibility test fix;
all other limits above remain unchanged. Current measurements belong to the
exact candidate and must be recomputed after each source change.

## Performance comparison in the SaaS fork

The downstream `saas-upgrade-benchmark.yml` workflow runs in this repository
and reuses the upstream seed, runner and comparator. Both measurements use one
current harness with the existing Server/Host/Runner interpreter redirects;
installed component revisions are checked outside either source tree. The
versions run sequentially in separate process sessions on the same runner to
keep cleanup from terminating a sibling benchmark or the CI controller. The
baseline is the PR's exact SaaS base commit. Locked installs, the upstream
P50/P95 thresholds, and ten required Session/Host journeys remain mandatory. A regression, missing journey, missing baseline or absent comparison
fails the SaaS verdict. Official upstream workflows retain their repository restrictions.
These local/mock-provider benchmarks do not replace deployed multi-replica,
live-provider or production SLO evidence.

The retained desktop recovery browser tests follow upstream's replacement of
classic account switching with Sign out and Connect. The shell owns credential
clearing and the next browser sign-in; the renderer no longer supplies the
removed `browserSignIn` IPC override. Native and picker sign-out tests retain
the authorization, renewal-wait, credential-clearing and error assertions.
