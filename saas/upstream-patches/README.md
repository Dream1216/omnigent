# Upstream patch queue

Every `.patch` must have a ledger entry recording its owner, affected upstream
paths, tests, upstream issue or pull request, first/last replayed revisions, and
removal condition. Runtime monkey patches and whole-file overrides are not
accepted.

The `06c33aea` replay keeps adapter contract `0.2.0`: the Host factory and
Runner-entry changes are additive composition seams that preserve the existing
Runtime Partition wire protocol, receipt schema, and persisted compatibility
fields. A future wire or receipt change must bump the contract independently.

| Patch | Owner | Upstream path | Verification | Upstream status | Replay baseline | Removal condition |
|---|---|---|---|---|---|---|
| `0002-managed-session-initializer.patch` | SaaS Platform | `omnigent/db/utils.py` | Store adapter contract; shared-read bypass; real PostgreSQL Runtime RLS | Generic extension proposal pending | `06c33aea` | Remove when upstream exposes a per-transaction Store session initializer or equivalent hook |
| `0003-managed-runtime-adapter-seams.patch` | SaaS Platform | `omnigent/host/connect.py`; `omnigent/llms/_usage_observer.py` | official Host/daemon/usage-observer tests; managed Provider metering adapter tests | Generic Host factory, reviewed Runner entrypoint, daemon lifecycle-lock, and required usage-sink extension proposal pending | `06c33aea` | Remove when upstream exposes equivalent Host construction, Runner entrypoint, daemon ownership, and fail-closed accounting seams |
| `0004-agent-cache-atomic-publish.patch` | Runtime Compatibility | `omnigent/runtime/agent_cache.py` | deterministic concurrent cache-miss regression; official AgentCache suite; server-integration session usage regression; upstream path-validation suite | Upstream now rejects unsafe cache paths; atomic publication/rollback remains downstream | `06c33aea` | Remove when upstream also serializes same-agent cache mutation and publishes only fully parsed extraction directories |
| `0005-external-host-runtime-bridge.patch` | SaaS Runtime | `omnigent/host/connect.py`; `omnigent/host/identity.py`; `omnigent/inner/bwrap_sandbox.py`; `omnigent/runner/_entry.py`; `omnigent/runner/identity.py`; `omnigent/runner/transports/ws_tunnel/serve.py`; `omnigent/server/routes/host_tunnel.py`; `omnigent/stores/host_store.py` | owner-only rotatable token-file contract; physical workspace propagation across Host spawn, Runner bootstrap, callback, and tunnel paths; tenant tunnel-route isolation; revocation heartbeat; exact expiry boundary; explicit Kubernetes container-proc sandbox contract | Generic external Host credential/file-source, Runtime Partition selector propagation, and Kubernetes nested-sandbox proposal pending | `06c33aea` | Remove when upstream supports file-backed external Host credentials, path-bound workspace propagation for managed Runners, an explicit tenant route, reconnect rotation, live revocation fencing, and a vetted Kubernetes proc-bind backend |
