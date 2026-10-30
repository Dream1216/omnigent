# Aliyun Host model admission candidate

This is P3 implementation work. It does not enable the production provider or
admit a release. Registry selection does not change this model channel.

The cloud Host must receive only its own launch token and a server-signed model
lease. The lease binds the Host ID, launch-token digest and authorized Runtime
Context. Its signing key and tenant model signing keys stay on the Server.
The maximum lease lifetime is 7200 seconds; it cannot replace the Host token.

For each credential renewal, the broker checks the current workspace, live Host
credential, active control-plane memberships, security versions, placement,
project authorization, session ownership and Host/session binding. It selects
only the explicitly configured tenant authority, without a fallback tenant.
The result is a tenant/session-bound model bearer lasting at most 300 seconds
and never beyond the lease expiry. Revocation prevents further issuance; a
previously issued bearer may remain usable until its bounded expiry.

The Host client uses one explicit HTTPS control-plane origin, disables proxy
environment inheritance and redirects, bounds response size and checks the
returned tenant/session/lifetime. The Host-owned relay uses an explicitly
configured HTTPS model endpoint. Runner processes receive only a random
loopback channel capability. Remote credential acquisition runs outside the
relay event loop. Existing pre-admission expiry recovery and the prohibition
on replaying started or ambiguous model requests remain in place.

The machine-auth middleware permits the broker's exact POST route only when
`host_model_broker_enabled=True`. The default is closed. It rejects mixed user
and Host credentials, other HTTP methods and unrelated paths. A workspace
header is a routing hint, not authorization; the signed lease and live stores
must independently admit that workspace and session.

Remaining integration and acceptance:

- Wire the broker and explicit profile into production Server composition.
- Admit the opt-in tenant factory through the production release profile.
- Verify the dedicated cloud Host entrypoint and owner-only file delivery in a
  real MicroVM. The scoped launcher now stages these files through the SDK,
  launches `saas.production.aliyun_host`, and removes its private directory on
  startup failure. Its commands and process arguments contain file references.
- Complete absolute-lifetime and lease-expiry behavior; a rolling SDK timeout
  must not keep a Host alive beyond its admitted model/launch credential lifetime.
- Configure public TLS callback and model gateway ingress without broadening
  ordinary SaaS authentication or exposing the gateway signing authority.
- Exercise a real Host, isolated Runner, model request, renewal, revocation and
  cleanup in a generation-2 Aliyun MicroVM.
- Complete image qualification, persistent storage, operations and P5 release
  acceptance before reporting the integration as online.

Local verification from the repository root:

```bash
.venv/bin/pytest tests/saas/test_aliyun_model_lease.py \
  tests/saas/test_aliyun_host.py tests/saas/test_aliyun_host_launcher.py \
  tests/saas/test_aliyun_tenant_sandbox.py \
  tests/saas/test_aliyun_model_broker.py tests/saas/test_aliyun_model_client.py \
  tests/saas/test_control_plane_resolver.py tests/saas/test_http_cookie_auth.py \
  tests/saas/test_platform_model_relay.py tests/saas/test_platform_model_runtime.py \
  tests/saas/test_platform_model_gateway.py -q
```

These tests cover current SQLite-backed admission and synthetic model transport.
They do not prove PostgreSQL RLS, real cloud boot, public ingress or production
deployment.
