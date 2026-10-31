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
   `RuntimeDefault` seccomp (the exact schema-v3 Runner execution exception below is separately reviewed), and all Linux capabilities dropped.
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

## Exact Runner execution seccomp (schema v3)

Only the `runner-agent` execution container in each canonical Runner deployment
uses `Localhost` at `omnigent/bubblewrap-v3.json`, full SHA-256
`c500aa5e6862ba7d50e54dcff65bf39120eb6f5300e548fc6e599bc58fcba363`.
Pod and init profiles and all other components remain `RuntimeDefault`.
The Runner keeps UID/GID 65532, dropped ALL capabilities, no-new-privileges,
read-only root, private PID, `hostPID: false`, and
`shareProcessNamespace: false`. Its trusted outer-backend marker is
`OMNIGENT_HOST_SANDBOX_BACKEND=kubernetes`; its existing RuntimeClass is
`omnigent-runner`. Neither that name nor a Node label proves effective isolation.

The authorized operator must capture fresh node UID, Pod ownership/UID, execution
container ID and digest, effective CRI/profile/process facts, and the actual
root-owned regular profile file using no-follow open and stable pre/post inode,
metadata and full byte hash. Bind the kernel/runtime, private PID namespace,
all effective init profiles, source revision, time and immutable raw artifact
hash to each placement. Retain the original bootstrap and activated inner-filter
positive/negative probes. Missing observations, unknown mapping, stale receipts,
a short hash label alone, or a changed runtime require rejection and new capture.
No maintained deployment-record collector is configured by this document: the
Root-owned raw node/CRI/probe adapter must be reviewed and actually executed.
Local unit fixtures are not node evidence and must never be signed as actuals.

Policy and record schema versions must match. V2 remains RuntimeDefault-only;
old V2 records are never automatically upgraded into V3 evidence. V3 selects only
the exact Runner contract above. All original replica/failure-domain, database,
network, 30-day age, rollback/P5 and distinct SRE/security/release-engineering
requirements remain. Recreate the whole-file admission receipt with the existing
signing identities and immutable raw artifact; no new signer or exemption is
introduced. The schema/rule change itself needs explicit human approval before
formal adoption, independently of local tests or successful kernel probes.

The V3 profile was captured for `containerd://2.3.2-k3s2`; that exact runtime
is required. Any runtime upgrade needs new capture/review rather than assuming
compatibility. Kernel releases must be observed legal versions, not UNKNOWN.
Each Runner instance needs its own current container ID and raw-evidence hash;
one aggregate/old probe hash cannot be reused for two physical placements.

Runner Pod, stage init, execution container and fsGroup must all use the normal
execution-profile UID/GID 65532. The original stager creates owner-only 0400
files and 0700 directories as that same user; do not stage as another UID or
weaken owner checks. Other component identities remain unchanged. The Runner
uses its explicit work/repository/runtime mounts; this contract does not add a
HOME override or infer UID switching from HOME/USER environment strings.
