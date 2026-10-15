# Omnigent 0.19 SaaS adoption boundary

The source baseline is `v0.19.0.dev20261015`, commit
`09152b0a15af5075f20dd8f9178066957908a810`. The initial rollout retains
adapter contract `0.2.0`, Runner Session initialization protocol `2`, official
schema head `mm1a2b3c4d5e`, and control-plane head `p0s000000015`.
Unchanged schema heads do not replace old-data, RLS, restore or N-1 tests.

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
- The ADR candidate is refreshed with `review_required` intact. Historical
  approvals and evidence remain immutable and do not approve this release.

## Release requirements

Run the protected SaaS upstream and N-1 workflows, the official affected suites,
Agent and authenticated online gates, PG18/PG16 and restore contracts, and image
supply-chain checks. Promote digest-pinned Server/Host/Runner components together
after mixed-version and draining behavior is proven. Complete the policy-defined
canary and N-1 rollback drill before final production admission. The initial
capability boundary is not a substitute for those gates.

## Trusted main review

The candidate refreshes only the exact `pyproject.toml` and `uv.lock` hashes
in the N-1 input allowlist, retaining the current 0.18 main hashes. It does not
change the evaluator, workflow identity, required assertions or acceptance
logic. Upstream also changes ten GitHub workflows. The trusted main evaluator
requires explicit administrator review for policy and automation changes and
will reject this candidate until that review is resolved. A candidate-side
green test does not authorize that merge or any production promotion.

## Performance comparison in the SaaS fork

The downstream `saas-upgrade-benchmark.yml` workflow runs in this repository
and reuses the upstream seed, runner and comparator. Its comparison uses the PR's exact SaaS base commit on the same runner,
locked installs, the upstream P50/P95 thresholds, and ten required Session/Host
journeys. A regression, missing journey, missing baseline or absent comparison
fails the SaaS verdict. Official upstream workflows retain their repository restrictions.
These local/mock-provider benchmarks do not replace deployed multi-replica,
live-provider or production SLO evidence.
