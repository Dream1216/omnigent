# Production deployment and failure-domain drill

Use this runbook to produce the deployment evidence required by the P4 containment,
two-failure-domain, and N-1 rollback gates. Readiness, replica counts, and logical
Kubernetes nodes are insufficient: the drill must prove distinct physical hosts in at
least two availability zones and continue to enforce every tenant and sandbox fence.

## Before the drill

1. Pin the exact product, upstream, adapter, schema, and image digests. Verify the image
   release policy before changing traffic.
2. Hash cluster, node, Pod, and deployment identities before placing them in the
   repository record. Store raw inventory only in the restricted immutable artifact.
3. Resolve physical host identity from the cloud instance/host authority, not only a
   Kubernetes Node name. Reject duplicate system UUIDs, provider IDs, or host hashes.
4. Verify all required components have two ready replicas, a disruption budget, hard
   anti-affinity/topology spread, digest-pinned images, dedicated ServiceAccounts, no
   host namespace, no privileged mode, no privilege escalation, read-only root filesystems,
   `RuntimeDefault` seccomp, and all Linux capabilities dropped.
5. Verify default-deny ingress/egress, metadata and private control-plane denial,
   proxy-only Runner egress, restricted DNS, isolated Preview origin, Runner-local UDS,
   and mTLS on Runner control and Preview relay paths from live policy and packet probes.
6. As a cluster owner or audited superuser, prove every database has removed
   `PUBLIC` `CONNECT`, `CREATE`, and `TEMPORARY`; prove each Runner LOGIN and the
   `saas_runner_agent` base role can effectively connect only to the exact
   receipt-bound database and cannot create temporary objects anywhere.
7. Prove every Runner-mutated Worktree, quota, Preview, and Outbox transition is
   enforced by a narrow database RPC or equivalent `OLD` to `NEW` trigger. A
   successful isolated-Beta run using raw table DML is not production evidence.

## Failure matrix

Run one controlled scenario at a time and preserve timestamps plus artifact digests:

- loss of each failure domain and a network partition between domains;
- control-plane, Runner, Preview Edge, and standalone Preview Owner replica loss;
- direct egress bypass, metadata access, DNS rebinding, and secret-exfiltration probes;
- stale lease/fencing replay;
- cross-database Runner connection, capability-action substitution, disabled or
  non-FORCE RLS, catalog/default-ACL drift, and raw-SQL lifecycle forgery;
- candidate to signed N-1 rollback, completed within 900 seconds.

During every scenario verify authorization, RLS, fairness, fencing, the exact Preview
Placement plus Runner connection generation, one-use exchange/session replay denial,
secret revocation, and cross-Tenant denial. Stop immediately if isolation weakens.
Restore normal capacity before starting the next scenario.

## Evidence and admission

Publish the raw probe bundle and DSSE envelope to an approved immutable store. The SRE,
security, and release-engineering actors must be distinct and attest only after the last
drill completes. Then create the hash-only canonical record and run:

```bash
uv run python -m saas.scripts.check_deployment_readiness \
  --product-revision "$EXACT_PRODUCT_REVISION" \
  --require-ready \
  --output artifacts/deployment-readiness-report.json
```

CI omits `--require-ready`; an empty evidence directory must remain structurally valid
and production-blocked. Never turn a local or single-host rehearsal into production
evidence.
