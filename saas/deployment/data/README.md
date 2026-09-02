# Beta PostgreSQL data plane

This directory defines the small, reviewable contract for the Beta PostgreSQL
data plane. It is not production evidence and does not claim that a cluster,
backup, or restore drill has run.

## Fixed compatibility boundary

- CloudNativePG `1.30.0`, using the official release manifest at
  `https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v1.30.0/cnpg-1.30.0.yaml`
  with SHA-256
  `f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88`.
- PostgreSQL `18.4` using the reviewed `18.4-standard-bookworm` image.
- Barman Cloud Plugin `0.14.0`, using its official release manifest with
  SHA-256
  `8d4f1719cc54891ddffd7633279ec93b5d2cc547df8684c3b84f3b156a615e7c`.
- cert-manager `1.21.1`, using `cert-manager.yaml` with SHA-256
  `5f6a499b8c1857d57f560f536e0dcc830914b45c420899fe7ad0692c8624e408`.
- Every CNPG, PostgreSQL, Barman, and cert-manager runtime image is the exact
  reviewed `linux/amd64` child-manifest digest encoded by the owner spec. The
  offline renderer checks those frozen references but does not query a registry
  or claim fresh remote verification.
- k3s / Kubernetes `1.36`.
- One PostgreSQL instance. Three Kubernetes nodes on one physical host are
  explicitly **not high availability**.

The canonical owner spec is ASCII JSON with sorted keys, compact separators,
one trailing newline, mode `0400` or `0600`, one link, and no extra fields. The
renderer rejects oversized or non-canonical input, defaults, placeholders,
unpinned images, zero digests, default-route CIDRs, unsafe retention, and
unexpected resources in upstream manifests.

## Offline render

Download the three public release manifests into an owner-controlled temporary
directory outside Git. Do not put credentials in those files. Then run:

```text
python -m saas.scripts.render_beta_postgresql_data_plane \
  --spec /absolute/owner/beta-postgresql.json \
  --cert-manager-manifest /absolute/tmp/cert-manager-v1.21.1.yaml \
  --operator-manifest /absolute/tmp/cnpg-1.30.0.yaml \
  --plugin-manifest /absolute/tmp/barman-plugin-0.14.0.yaml \
  --output-directory /absolute/release/beta-postgresql
```

The command performs no network access. It verifies the exact source bytes;
pins the three cert-manager images plus the CNPG operator, Barman operator, and
Barman sidecar images; removes the upstream non-credential `SIDECAR_IMAGE`
Secret in favor of a direct pinned environment value; rejects every other
Secret and unexpected image-bearing cert-manager workload; and emits each
resource as a separate file smaller than 1 MiB. The atomic receipt says
`rendered_not_applied`, `restore_drill_execution: not_executed`, and that the
restore package requires explicit authorization.

The output root is a receipt container, not an apply target. Never run a
recursive apply against it. Installation and the normal Beta release are
separate, explicit gates. cert-manager must become healthy before CNPG or the
Barman plugin is installed:

```text
kubectl apply -f /absolute/release/beta-postgresql/upstream/cert-manager
kubectl rollout status deployment/cert-manager -n cert-manager --timeout=2m
kubectl rollout status deployment/cert-manager-cainjector -n cert-manager --timeout=2m
kubectl rollout status deployment/cert-manager-webhook -n cert-manager --timeout=2m
cmctl check api --wait=2m

kubectl apply -f /absolute/release/beta-postgresql/upstream/operator
kubectl rollout status deployment/cnpg-controller-manager -n cnpg-system --timeout=2m

kubectl apply -f /absolute/release/beta-postgresql/upstream/barman-plugin
kubectl wait --for=condition=Ready issuer/selfsigned-issuer -n cnpg-system --timeout=2m
kubectl wait --for=condition=Ready certificate/barman-cloud-client -n cnpg-system --timeout=2m
kubectl wait --for=condition=Ready certificate/barman-cloud-server -n cnpg-system --timeout=2m
kubectl rollout status deployment/barman-cloud -n cnpg-system --timeout=2m
kubectl get events -n cnpg-system --field-selector reason=PluginRegistered

kubectl apply -f /absolute/release/beta-postgresql/primary
```

Do not apply `primary/` until the Barman Issuer and both certificates are Ready,
their TLS Secrets exist, the Barman Deployment is Ready, and the CNPG operator
has emitted the `PluginRegistered` event for the `barman-cloud` Service. The
owner-provided database and object-store Secrets must also exist before this
final step.

The `primary/` package contains no restore namespace, restore ObjectStore, or
restore Cluster, so the normal apply cannot start a PITR drill. Only after an
independent, recorded restore-drill authorization may an operator run:

```text
kubectl apply -f /absolute/release/beta-postgresql/restore-drill
```

Applying a directory still requires the release receipt and artifact hashes to
be verified first. The example commands describe package boundaries; they do
not constitute deployment evidence.

The final bundle contains:

- a `Retain`, `WaitForFirstConsumer` StorageClass with prune protection;
- separate data and WAL storage, initdb data checksums, TLS Secret references,
  an external bootstrap-owner Secret reference, `max_notify_queue_pages=64`,
  and `max_prepared_transactions=0`;
- an ObjectStore, WAL archiver plugin, and six-field plugin-method
  ScheduledBackup with a bounded retention window;
- default-deny data, restore, and `cnpg-system` policies with only reviewed
  DNS, Kubernetes API, webhook `9443`, PostgreSQL `5432`, CNPG status `8000`,
  operator-to-plugin and instance-to-plugin `9090`, and object-store HTTPS
  `443` paths;
- a physically separate `restore-drill/` package containing an isolated
  point-in-time restore Cluster which deliberately does not enable WAL
  archiving back into the source store; and
- `restore-drill-evidence.schema.json`, which rejects false-pass records and
  requires structured failure evidence. The Python admission validator also
  binds canonical evidence to the exact deployment, spec, bundle, recovery
  target, non-zero Kubernetes UIDs, and ordered UTC timestamps. Rendering the
  drill manifest is not execution evidence.

The owner must provision the named bootstrap, TLS, and object-store credential
Secrets independently in both data and restore namespaces where referenced.
This renderer never creates Secret values. Before applying restrictive
`cnpg-system` policies, the owner must confirm the observed Kubernetes API,
control-plane, and node source CIDRs used for webhook and kubelet probes.
Schema admission is necessary but not sufficient production proof. Signed or
otherwise immutable external evidence storage remains a later execution gate.

## Reviewed primary sources

- CloudNativePG 1.30 release and asset:
  <https://github.com/cloudnative-pg/cloudnative-pg/releases/tag/v1.30.0>
- CloudNativePG backup and six-field schedules:
  <https://cloudnative-pg.io/docs/1.30/backup/>
- Bootstrap and data checksums:
  <https://cloudnative-pg.io/docs/1.30/bootstrap/>
- TLS certificate references:
  <https://cloudnative-pg.io/docs/1.30/certificates/>
- Storage and WAL volumes:
  <https://cloudnative-pg.io/docs/1.30/storage/>
- Operator connectivity (`5432` and `8000`):
  <https://cloudnative-pg.io/docs/1.30/networking/>
- CNPG-I service discovery, mTLS, and plugin port:
  <https://cloudnative-pg.io/docs/1.30/cnpg_i/>
- Barman Cloud Plugin 0.14 release:
  <https://github.com/cloudnative-pg/plugin-barman-cloud/releases/tag/v0.14.0>
- ObjectStore, WAL archiver, backup, and recovery syntax:
  <https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/v0.14.0/web/versioned_docs/version-0.14.0/usage.md>
- Barman backup/PITR model:
  <https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/v0.14.0/web/versioned_docs/version-0.14.0/concepts.md>
- Barman plugin parameters:
  <https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/v0.14.0/web/versioned_docs/version-0.14.0/parameters.md>
- Barman plugin installation requirements:
  <https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/v0.14.0/web/versioned_docs/version-0.14.0/installation.mdx>
- cert-manager 1.21.1 release and static manifest:
  <https://github.com/cert-manager/cert-manager/releases/tag/v1.21.1>
- cert-manager static-manifest installation and readiness:
  <https://cert-manager.io/docs/installation/kubectl/>
- Kubernetes default-deny and DNS implications:
  <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
