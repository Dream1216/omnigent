# Preview Gateway deployment contract

These assets run one downstream-owned Preview Gateway process without changing the
official Omnigent server or Runner. They are a hardened deployment baseline, not
evidence that a production environment, external CA/HSM, or failure domain exists.

The executable is:

```text
omnigent-saas-preview-gateway \
  --config /etc/omnigent/preview-gateway/gateway-a.json \
  --factory omnigent_saas_deployment.preview_gateway:factory
```

The JSON file is non-secret and must be an absolute, regular, root/current-user-owned
file that is not group/other writable. A process-unique Gateway ID and registration
token are generated in memory on every start; neither may be placed in the file.

The trusted `module:attribute` factory must return
`PreviewGatewayProcessComponents`. It owns these deployment-specific integrations:

- an mTLS workload client for privileged registration, certificate metadata
  activation/revocation, heartbeat, drain, and release operations;
- an external CA plus local/HSM key provider that never returns private-key bytes to
  the lifecycle coordinator;
- a TLS 1.3 Relay listener and client state whose leaves are installed atomically;
- `MutualTlsPreviewGatewayReadinessProbe` configured with a separately provisioned
  platform-health identity, never the still-disabled Gateway client leaf;
- a persistent Placement drain observer.

The factory must not give the Gateway a `saas_platform` PostgreSQL credential. The
process is an unprivileged workload; privileged state transitions belong behind an
authenticated control-plane API with a narrow method policy. Factory loading is a
deployment-time trust decision and must not be tenant configurable.

`/livez` and `/readyz` are exposed only on the configured loopback IP. Kubernetes uses
the executable's loopback `--probe` mode, so the health socket is not exposed on the
Pod network. `/readyz` becomes successful only after the Relay listener, certificate
pair, independent TLS probe, and durable `starting -> active` transaction complete.

The Kubernetes example deliberately starts with one replica: its static example
endpoint must never be shared by multiple process identities. Before scaling, the
deployment factory/config renderer must assign each Pod a server-selected, directly
routable endpoint and matching certificate name; a Service VIP that can land on the
wrong Placement owner is invalid.

The systemd unit and Kubernetes manifest intentionally keep all production-specific
image digests, factory module names, CA/HSM mounts, control-plane endpoints, Network
Policy allowlists, and resource limits as deployment inputs. Before production GO,
replace every marker, pin an immutable signed image digest, restrict egress to the
control plane/CA/observability destinations, validate external Trust Bundle overlap
and rollback, and execute cross-host partition plus N-1 rollback tests in two failure
domains.
