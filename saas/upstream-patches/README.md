# Upstream patch queue

Every `.patch` must have a ledger entry recording its owner, affected upstream
paths, tests, upstream issue or pull request, first/last replayed revisions, and
removal condition. Runtime monkey patches and whole-file overrides are not
accepted.

Replay permits zero-context unified hunks so generated patches remain compatible
with the repository's trailing-whitespace hook. This does not relax the binding:
every patch is applied only to the pinned upstream revision, and the checker
then requires every replayed official-source byte to match the product tree.

The `06c33aea` replay keeps adapter contract `0.2.0`: the Host factory and
Runner-entry changes are additive composition seams that preserve the existing
Runtime Partition wire protocol, receipt schema, and persisted compatibility
fields. A future wire or receipt change must bump the contract independently.

The 2026-09-13 external Host registration correction is carried by patch 0005.
The token resolver and atomic registration both reject `expires_at <= now`.
Registration accepts either a provider plus live sandbox id (including a
previous generation still pending cleanup), or an explicitly armed external
Host with all three lifecycle fields absent. Token, owner, workspace and
deletion predicates remain in the same atomic UPDATE. The SQLite/PostgreSQL
matrix in `tests/saas/test_external_host_registration.py` covers all eight
lifecycle tuples, expiry boundaries, revalidation after mutation, reconnect,
rotation, and the real ASGI `host.hello` registration path.

Source-budget scope: the user requested candidate and budget closure on
2026-09-13. `external-host-atomic-registration-v1` adds exactly 13 net lines
to the existing `host_store.py` seam, taking the measured ceiling from 812
to 825. The 30-file limit, 8-patch limit, isolation ratio, forbidden paths and
reverse-dependency checks are unchanged. This is a Single-Owner Beta source
budget revision, not an independent reviewer signature, merge waiver or
production admission. A further source increase must be reviewed separately.

The separately authorized `secure-saas-browser-logout-v1` revision raises the
measured ceiling from 30 files / 825 net lines to 33 files / 1,047 net lines.
The three additional direct files are the Settings page, its test and the Vite
proxy config; the 222 net-line increase spans the identity, settings and
development-proxy seams. It makes Accounts, SaaS and OIDC logout explicit,
preserves same-origin and CSRF checks, clears local state only after server
revocation succeeds, and exposes only the SaaS auth and login surfaces to the
development proxy. The 8-patch ceiling, isolation floor, forbidden paths and
reverse-dependency checks remain unchanged. This remains a Single-Owner Beta
budget record, not production admission or a merge waiver.

The `platform-managed-model-catalog-v1` revision adds one generic Pi gateway
catalog seam. A gateway family now publishes every configured model value to
Pi instead of only its default/selected model. The platform adapter therefore
keeps the Provider secret outside official configuration, supplies only the
Credential Proxy environment-variable name, and exposes the administrator's
exact allowlist in the ordinary model picker. This raises the measured ceiling
from 33 files / 1,047 net lines to 34 files / 1,055 net lines and the active
patch count from four to five. The change imports no SaaS package and remains
independently removable when upstream supports multi-model inline gateways.
It is a Single-Owner Beta source-budget record, not production admission.

The `harness-fleet-qwen-opencode-v1` revision pins the official Qwen Code and
OpenCode packages in the Host image and routes OpenCode through the existing
OpenAI-compatible platform Provider with only the session-bound synthetic
gateway credential. The generated pnpm lock, install policy, image checks and
positive/negative routing tests raise the measured ceiling from 39 files /
1,323 net lines to 47 files / 2,119 net lines. Patch 0007 carries the three
official Python seams; the initially proposed native Runner edit was removed,
so forbidden paths, reverse dependencies, the 0.85 isolation floor and the
8-patch ceiling are unchanged. This is a Single-Owner Beta scope record, not
production admission, vendor-account authentication or a merge waiver.

| Patch | Owner | Upstream path | Verification | Upstream status | Replay baseline | Removal condition |
|---|---|---|---|---|---|---|
| `0002-managed-session-initializer.patch` | SaaS Platform | `omnigent/db/utils.py` | Store adapter contract; shared-read bypass; real PostgreSQL Runtime RLS | Generic extension proposal pending | `06c33aea` | Remove when upstream exposes a per-transaction Store session initializer or equivalent hook |
| `0003-managed-runtime-adapter-seams.patch` | SaaS Platform | `omnigent/host/connect.py`; `omnigent/llms/_usage_observer.py` | official Host/daemon/usage-observer tests; managed Provider metering adapter tests | Generic Host factory, reviewed Runner entrypoint, daemon lifecycle-lock, and required usage-sink extension proposal pending | `06c33aea` | Remove when upstream exposes equivalent Host construction, Runner entrypoint, daemon ownership, and fail-closed accounting seams |
| `0004-agent-cache-atomic-publish.patch` | Runtime Compatibility | `omnigent/runtime/agent_cache.py` | deterministic concurrent cache-miss regression; official AgentCache suite; server-integration session usage regression; upstream path-validation suite | Upstream now rejects unsafe cache paths; atomic publication/rollback remains downstream | `06c33aea` | Remove when upstream also serializes same-agent cache mutation and publishes only fully parsed extraction directories |
| `0005-external-host-runtime-bridge.patch` | SaaS Runtime | `omnigent/host/connect.py`; `omnigent/host/identity.py`; `omnigent/inner/bwrap_sandbox.py`; `omnigent/runner/_entry.py`; `omnigent/runner/identity.py`; `omnigent/runner/transports/ws_tunnel/serve.py`; `omnigent/server/routes/host_tunnel.py`; `omnigent/stores/host_store.py` | owner-only rotatable token-file contract; physical workspace propagation across Host spawn, Runner bootstrap, callback, and tunnel paths; tenant tunnel-route isolation; revocation heartbeat; exact expiry boundary; explicit Kubernetes container-proc sandbox contract | Generic external Host credential/file-source, Runtime Partition selector propagation, and Kubernetes nested-sandbox proposal pending | `06c33aea` | Remove when upstream supports file-backed external Host credentials, path-bound workspace propagation for managed Runners, an explicit tenant route, reconnect rotation, live revocation fencing, and a vetted Kubernetes proc-bind backend |
| `0006-pi-gateway-model-catalog.patch` | SaaS Platform | `omnigent/harnesses/pi_native/credentials.py` | multi-model Platform gateway projection; secret-free Pi config; allowed-catalog picker regression | Generic upstream gateway-catalog proposal pending | `06c33aea` | Remove when upstream publishes all configured inline gateway models to Pi |
| `0007-opencode-platform-provider.patch` | SaaS Platform | `omnigent/harnesses/opencode_native/provider.py`; `omnigent/onboarding/harness_readiness.py`; `omnigent/onboarding/provider_config.py` | official OpenCode gateway resolution; configured-provider readiness; platform runtime synthetic-token routing; no native Runner edit | Generic upstream OpenCode provider-fallback proposal pending | `06c33aea` | Remove when upstream can route OpenCode through an OpenAI-compatible configured Provider without persisting its upstream credential |
