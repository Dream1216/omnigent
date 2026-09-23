# Upstream patch queue

Every `.patch` must have a ledger entry recording its owner, affected upstream
paths, tests, upstream issue or pull request, first/last replayed revisions, and
removal condition. Runtime monkey patches and whole-file overrides are not
accepted.

Replay permits zero-context unified hunks so generated patches remain compatible
with the repository's trailing-whitespace hook. This does not relax the binding:
every patch is applied only to the pinned upstream revision, and the checker
then requires every replayed official-source byte to match the product tree.

The `9616bf97` replay keeps adapter contract `0.2.0`: the Host factory and
Runner-entry changes are additive composition seams that preserve the existing
Runtime Partition wire protocol, receipt schema, and persisted compatibility
fields. A future wire or receipt change must bump the contract independently.

This baseline includes the upstream `c90e5de4` AgentSpec tool-grant enforcement
and `f754c140` sidecar MCP allow-list enforcement. The downstream queue does
not replace either security boundary. Patch 0003 owns the complete
`host/connect.py` delta so the Host factory, Runner entrypoint, interactive
shell inventory and external workspace propagation remain one replayable file;
patch 0005 owns the remaining external Host bridge paths.

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

The `harness-fleet-qwen-opencode-v2` revision pins the official Qwen Code and
OpenCode packages in the Host image and routes OpenCode through the existing
OpenAI-compatible platform Provider with only the session-bound synthetic
gateway credential. The generated pnpm lock, install policy, image checks and
positive/negative routing tests raise the measured ceiling from 40 files /
1,348 net lines to 48 files / 2,144 net lines. Patch 0007 carries the three
official Python seams; the initially proposed native Runner edit was removed,
so forbidden paths, reverse dependencies, the 0.85 isolation floor and the
8-patch ceiling are unchanged. This is a Single-Owner Beta scope record, not
production admission, vendor-account authentication or a merge waiver.

The `harness-fleet-qwen-e2e-fixture-v3` corrective revision binds the official
Qwen one-shot E2E to the active isolated mock-provider fixture. A real Host
with Qwen installed otherwise reaches setup and fails before the test body
because the removed fixture name cannot be resolved. This adds one directly
changed test file while reducing the measured net delta from 2,144 to 2,143
lines. The direct-file ceiling therefore moves from 48 to 49; the 2,144-line
ceiling, patch count, isolation floor, forbidden paths and reverse-dependency
checks remain unchanged. This is a Single-Owner Beta corrective record, not
production admission or a merge waiver.

The `harness-fleet-qwen-e2e-snapshot-v5` corrective revision adds the missing
deterministic Qwen one-shot acceptance snapshot. Once the active credential
fixture allowed the Host-installed CLI to execute, the exact-SHA E2E shard
correctly rejected the absent contract before evaluating the result. The new
five-line snapshot requires zero exit status, clean stderr and non-empty
assistant text. Together with the one-line build-aware CI shard correction,
the measured source delta is exactly 50 files / 2,148 net lines; the hard
ceilings are raised only to those values. Patch count, isolation floor,
forbidden paths and reverse-dependency checks remain unchanged. This is a
Single-Owner Beta corrective record, not production admission or a merge
waiver.

The `harness-fleet-kimi-provider-v6` revision pins the official
`@moonshot-ai/kimi-code` package and routes both headless and native Kimi
through the existing OpenAI-compatible platform Provider. Only the Host's
session-bound synthetic token is exported through Kimi's `KIMI_MODEL_*`
process environment; neither that token nor the upstream Provider key is
written to `config.toml`. Patch 0008 carries seven official Kimi/onboarding
seams. The initially proposed workflow and native Runner edits were removed,
so forbidden paths remain untouched. Install, image-material, readiness,
temporary-provider, secret-persistence and vendor-login fallback tests plus
the async spawn-environment canary raise the exact measured totals from 50
files / 2,148 net lines to 62 files / 2,575 net lines and the active patch
count from six to seven. The 8-patch ceiling,
0.85 isolation floor and reverse-dependency checks remain unchanged. This is a
Single-Owner Beta scope record, not production admission, vendor-account
authentication or a merge waiver.

The 2026-09-21 managed Host daemon correction carries the configured workspace
selector through CLI backgrounding into the daemon and Runner process. Patch
0009 owns the two-line `omnigent/cli.py` delta and the focused CLI-to-daemon
regression verifies propagation while retaining the existing Provider-secret
exclusion. The executable regression remains isolated under `tests/saas/`.
This raises the active patch count from seven to the existing hard ceiling of
eight and the direct-file ceiling from 69 to the exact measured 70; the 2,579
net-line ceiling, isolation floor, forbidden paths and reverse-dependency
checks remain unchanged. This is a Single-Owner Beta corrective record, not
production admission or a merge waiver.

The `dual-managed-kubernetes-runtimes-v12` revision expands that same final
patch slot with the bounded
operator-owned `host_command` seam needed to launch the managed Host inside
either a Kubernetes Agent Sandbox CR or an ordinary Kubernetes Job. Patch
0009 carries the three official Python paths while platform-model credential
projection, production configuration, image construction and admission tests
remain isolated under `saas/`. The exact measured source delta is 76 direct
files / 2,229 net lines, retaining the eighth and final active patch slot while
retaining the 2,579-line ceiling, 0.85 isolation floor, forbidden paths and
reverse-dependency checks. This is an authorized Single-Owner Beta scope
record, not production admission, reviewer approval or a merge waiver.

The `harness-readiness-release-verification-v14` revision further expands the
existing final patch slot with Kiro's supported device-flow login command and
revocation-aware `whoami` probe.  Picker readiness can now distinguish an
installed Kiro binary from a vendor-authenticated Kiro session, while the
launch gate remains binary-only.  The protected release workflow also pulls
the published Host digest and verifies that every default Harness CLI is
present and version-compatible before signing.  Exact measured source delta is
unchanged at 81 files and rises from 2,313 to 2,364 net lines, within the
existing 2,579-line ceiling.  The 8-patch ceiling, isolation floor, forbidden
paths and reverse-dependency checks remain unchanged.  This is a Single-Owner
Beta corrective record, not vendor-account authentication or production
admission.

The `kiro-readiness-regression-contract-v15` revision aligns the pre-existing
official Kiro readiness regression with that structured picker contract:
missing Kiro now asserts `binary-missing` instead of the legacy boolean value.
This changes one additional direct test file but adds no measured net lines,
moving the exact source delta from 81 files / 2,364 lines to 82 files / 2,364
lines.  Only the direct-file ceiling rises to the exact measured 82; the 2,579
LOC ceiling, 8-patch ceiling, isolation floor, forbidden paths and
reverse-dependency checks remain unchanged.  This is a Single-Owner Beta
corrective record, not production admission or a technical-gate waiver.

| Patch | Owner | Upstream path | Verification | Upstream status | Replay baseline | Removal condition |
|---|---|---|---|---|---|---|
| `0002-managed-session-initializer.patch` | SaaS Platform | `omnigent/db/utils.py` | Store adapter contract; shared-read bypass; real PostgreSQL Runtime RLS | Generic extension proposal pending | `9616bf97` | Remove when upstream exposes a per-transaction Store session initializer or equivalent hook |
| `0003-managed-runtime-adapter-seams.patch` | SaaS Platform | `omnigent/host/connect.py`; `omnigent/llms/_usage_observer.py` | official Host/daemon/usage-observer tests; managed Provider metering adapter tests; external workspace propagation | Generic Host factory, reviewed Runner entrypoint, daemon lifecycle-lock, and required usage-sink extension proposal pending | `9616bf97` | Remove when upstream exposes equivalent Host construction, Runner entrypoint, daemon ownership, and fail-closed accounting seams |
| `0004-agent-cache-legacy-recovery.patch` | Runtime Compatibility | `omnigent/runtime/agent_cache.py` | legacy partial-cache rebuild regression; official atomic publication and rollback suite | Upstream publishes and rolls back staging directories atomically; corrupt legacy-cache recovery remains downstream | `9616bf97` | Remove when upstream recovers corrupt legacy cache entries |
| `0005-external-host-runtime-bridge.patch` | SaaS Runtime | `omnigent/host/identity.py`; `omnigent/inner/bwrap_sandbox.py`; `omnigent/runner/_entry.py`; `omnigent/runner/identity.py`; `omnigent/runner/transports/ws_tunnel/serve.py`; `omnigent/server/routes/host_tunnel.py`; `omnigent/stores/host_store.py` | owner-only rotatable token-file contract; physical workspace propagation across Runner bootstrap, callback, and tunnel paths; tenant tunnel-route isolation; revocation heartbeat; exact expiry boundary; explicit Kubernetes container-proc sandbox contract | Generic external Host credential/file-source, Runtime Partition selector propagation, and Kubernetes nested-sandbox proposal pending | `9616bf97` | Remove when upstream supports file-backed external Host credentials, path-bound workspace propagation for managed Runners, an explicit tenant route, reconnect rotation, live revocation fencing, and a vetted Kubernetes proc-bind backend |
| `0006-pi-gateway-model-catalog.patch` | SaaS Platform | `omnigent/harnesses/pi_native/credentials.py` | multi-model Platform gateway projection; secret-free Pi config; allowed-catalog picker regression | Generic upstream gateway-catalog proposal pending | `9616bf97` | Remove when upstream publishes all configured inline gateway models to Pi |
| `0007-opencode-platform-provider.patch` | SaaS Platform | `omnigent/harnesses/opencode_native/provider.py`; `omnigent/onboarding/harness_readiness.py`; `omnigent/onboarding/provider_config.py` | official OpenCode gateway resolution; configured-provider readiness; platform runtime synthetic-token routing; no native Runner edit | Generic upstream OpenCode provider-fallback proposal pending | `9616bf97` | Remove when upstream can route OpenCode through an OpenAI-compatible configured Provider without persisting its upstream credential |
| `0008-kimi-platform-provider.patch` | SaaS Platform | `omnigent/cli_config.py`; `omnigent/harnesses/kimi_native/credentials.py`; `omnigent/inner/kimi_executor.py`; `omnigent/inner/kimi_harness.py`; `omnigent/onboarding/harness_install.py`; `omnigent/onboarding/harness_readiness.py`; `omnigent/onboarding/provider_config.py` | official package install; headless/native temporary Provider routing; no persisted token; vendor-login fallback; no workflow/native Runner edit | Generic upstream Kimi temporary-provider proposal pending | `9616bf97` after patches 0002-0007 | Remove when upstream can install Kimi and route it through an OpenAI-compatible configured Provider without persisting its upstream credential |
| `0009-managed-kubernetes-runtime-providers.patch` | SaaS Runtime | `omnigent/cli.py`; `omnigent/onboarding/harness_install.py`; `omnigent/onboarding/harness_readiness.py`; `omnigent/onboarding/sandboxes/kubernetes.py`; `omnigent/server/managed_hosts.py` | Kubernetes SDK image material; bounded Host command and reserved server URL; workspace propagation; Agent Sandbox and Job provider parsing; Kiro device-flow login and `whoami` readiness; dual-provider production contracts | Generic upstream managed Kubernetes Host-command, multi-provider and Kiro readiness proposal pending | `9616bf97` after patches 0002-0008 | Remove when upstream exposes equivalent bounded managed-Host commands, reserved server/workspace propagation, composable Agent Sandbox plus Kubernetes Job providers, and revocation-aware Kiro readiness |
