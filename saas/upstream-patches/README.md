# Upstream patch queue

Every `.patch` must have a ledger entry recording its owner, affected upstream
paths, tests, upstream issue or pull request, first/last replayed revisions, and
removal condition. Runtime monkey patches and whole-file overrides are not
accepted.

The `e179bc42` replay keeps adapter contract `0.2.0`: the Host factory and
Runner-entry changes are additive composition seams that preserve the existing
Runtime Partition wire protocol, receipt schema, and persisted compatibility
fields. A future wire or receipt change must bump the contract independently.

| Patch | Owner | Upstream path | Verification | Upstream status | Replay baseline | Removal condition |
|---|---|---|---|---|---|---|
| `0002-managed-session-initializer.patch` | SaaS Platform | `omnigent/db/utils.py` | Store adapter contract; shared-read bypass; real PostgreSQL Runtime RLS | Generic extension proposal pending | `e179bc42` | Remove when upstream exposes a per-transaction Store session initializer or equivalent hook |
| `0003-managed-runtime-adapter-seams.patch` | SaaS Platform | `omnigent/host/connect.py`; `omnigent/llms/_usage_observer.py` | official Host/daemon/usage-observer tests; managed Provider metering adapter tests | Generic Host factory, reviewed Runner entrypoint, daemon lifecycle-lock, and required usage-sink extension proposal pending | `e179bc42` | Remove when upstream exposes equivalent Host construction, Runner entrypoint, daemon ownership, and fail-closed accounting seams |
| `0004-agent-cache-atomic-publish.patch` | Runtime Compatibility | `omnigent/runtime/agent_cache.py` | deterministic concurrent cache-miss regression; official AgentCache suite; server-integration session usage regression | Upstream issue/PR pending | `e179bc42` | Remove when upstream serializes same-agent cache mutation and publishes only fully parsed extraction directories |
| `0005-external-host-machine-credentials.patch` | SaaS Platform | `omnigent/cli.py`; `omnigent/cli_auth.py`; `omnigent/db/db_models.py`; `omnigent/db/migrations/versions/h8c0d1e2f3a4_add_host_credential_generation.py`; `omnigent/host/connect.py`; `omnigent/host/identity.py`; `omnigent/server/routes/host_tunnel.py`; `omnigent/server/routes/hosts.py`; `omnigent/stores/host_store.py` | Host identity/CLI/store/API suites; exact tunnel authentication; generation fencing; immediate revoke; workspace-zero compatibility | Generic external Host machine-credential proposal pending | `e179bc42` | Remove when upstream exposes equivalent file-backed Host identity, rotatable machine credential lifecycle, path-bound tunnel authentication, and workspace binding contracts |
