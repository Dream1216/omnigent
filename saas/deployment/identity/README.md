# Private identity process staging

`saas.scripts.render_identity_release` extends the existing trusted release
renderer. It preserves all four parent manifests and their evidence bytes and
adds `kubernetes.identity.yaml` and `identity-release-render-evidence.json`.
It accepts only the bundled parent sources, a staged release and the reviewed
`cd4a00000001` schema. Both identity Deployments have **zero replicas**. The
[identity release gate](../../production/identity-evidence/README.md) requires
current signed acceptance and measured live convergence. Final rendering remains
blocked pending deployment activation admission and the required live evidence.

The identity manifest contains separate database-free reader and authenticator
worker ServiceAccounts, Deployments, ClusterIP TLS Services, disruption budgets,
and ingress/egress NetworkPolicies. Neither ServiceAccount has RBAC grants or a
mounted API token. Containers run as UID/GID 10001, drop every capability, use
the runtime default seccomp profile and have read-only roots. Raw Secret volumes
are mounted only into each process's own init container. It copies a bounded
set of inputs into regular mode-0400 files on an in-memory volume; the main
container receives only that read-only snapshot and temporary memory storage.

The reader receives only its provider application secret, reader keyring, TLS
pair and provider CA. The worker receives only its reader secret, Webhook
keyring, TLS pair, reader CA, authenticator database URL, PostgreSQL CA and
sealed migration receipt. Both receive the same exact public customer pins,
source lock and release facts. Optional role profiles are copied from the
parent's public bindings without widening the worker's database authority.

The renderer never creates Secrets. Provision each referenced Secret as
immutable under its reviewed revisioned name. TLS Secrets contain `tls.crt`
and `tls.key`; CA Secrets contain `ca.crt`; other identity Secrets contain only
`value`. Secret names must be distinct and end in a twelve-character digest
suffix. Those names are deployment references, not proof of the Secret's
contents or immutability. Verify both against the external secret inventory.
The existing `omnigent-saas-authenticator-database`,
`omnigent-saas-postgresql-ca` and `omnigent-saas-migration-receipt` inputs keep
the parent release's ownership and validation requirements.

## Inputs and command

Use the existing canonical release spec plus a separate canonical owner-only
JSON identity spec with these fields. The values below are synthetic examples:

```json
{
  "schema_version": 1,
  "casdoor": {
    "issuer": "https://auth.identity.example.com",
    "organization": "customers",
    "application": "customer-web",
    "client_id": "customer-client",
    "provider_application": "private-state-reader",
    "provider_client_id": "private-machine-client",
    "endpoint_cidr": "203.0.113.12/32"
  },
  "reader_key_id": "current",
  "concurrency": 4,
  "reconcile_seconds": 60,
  "poll_seconds": 1,
  "private_ingress": {"namespace": "identity-private", "workload": "casdoor-webhook-relay"},
  "monitoring": {"namespace": "monitoring", "workload": "prometheus"},
  "secrets": {
    "provider": "identity-provider-111111111111",
    "reader_keys": "identity-reader-keys-222222222222",
    "reader_secret": "identity-reader-secret-333333333333",
    "webhook_keys": "identity-webhook-keys-444444444444",
    "broker_tls": "identity-broker-tls-555555555555",
    "worker_tls": "identity-worker-tls-666666666666",
    "provider_ca": "identity-provider-ca-777777777777",
    "reader_ca": "identity-reader-ca-888888888888"
  }
}
```

Canonical serialization is ASCII JSON with sorted keys, separators `,` and `:`,
and one final newline. Input files must be regular, non-symlink, owned by the
operator and mode 0400 or 0600. Keep actual credential values out of both specs.

```sh
python -m saas.scripts.render_identity_release \
  --release-spec /private/release-stage.json \
  --identity-spec /private/identity-stage.json \
  --output-dir /private/identity-stage-rendered
```

The output directory must be new or empty. It is mode 0700 and files are 0600.
Evidence binds the exact parent evidence, image, source revision, role bindings,
identity spec, generated public configuration and identity manifest. The parent
renderer remains responsible for namespace and service-DNS rewriting; the
identity resources use its fixed `omnigent-next-beta` target and dedicated CNPG
database peer in `omnigent-next-beta-data`.

## Review before admission

The reader can reach DNS and only the configured single provider IP on TLS
443. The worker can reach DNS, the private reader on TLS 8443 and the dedicated
PostgreSQL peer on 5432. Incoming traffic is limited to the exact namespace and
`app.kubernetes.io/name` selectors for the approved private Webhook transport,
monitoring and worker. There is no public Ingress, NodePort or LoadBalancer.
The private Webhook relay/peering route and monitoring system are externally
managed; this manifest does not create them or prove delivery. Resolve and
freeze the actual provider endpoint and qualify the CNI's Service/NAT behavior.
An endpoint change requires a reviewed re-render, not broad egress.

Issue the reader certificate for
`omnigent-identity-reader.omnigent-next-beta.svc.cluster.local`, and issue the
worker certificate for its private delivery name. Verify issuer, hostname,
rotation and revocation from the actual clients. Kubernetes health probes do
not replace that client verification. Exercise Pod rescheduling, startup
catalog verification, in-flight claim recovery, process termination, replica
failover and dependency outages under admitted load. Resource requests, limits
and preferred anti-affinity are candidate settings awaiting those measurements.

Before enabling replicas, verify private network denials and Secret exposure
from the actual Pods; install and exercise lag/dead-letter/readback alerts;
qualify audited dead-letter replay and matched product/IdP/key restore; and
prove direct authenticated Webhook delivery through the worker and real signed
OIDC sessions converges within 300 seconds. An independent identity admission
receipt and release gate must bind those facts to this exact rendering. A
successful stage render is not production qualification.

For manual review, compare the parent output bytes with a standalone parent
render, inspect zero replica counts and the `identity-admission-pending`
annotation, and check that reader and worker Secret sets are disjoint except
public configuration. Run `pytest tests/saas/test_render_identity_release.py`
to reproduce source-drift, overwrite, authority, network and closed-loader
checks without connecting to production.
