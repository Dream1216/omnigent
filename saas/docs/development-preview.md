# Session development previews

The expanded session preview control discovers HTTP listeners belonging to that
session every three seconds. Start a development server in the session's terminal
or Shell tool, then choose **打开开发预览**. A completed delivery run or build is
not required. The existing static preview remains a checkpoint snapshot.

## Sub-features

- `owned-listeners`: inspect real terminal/helper process ownership and listening
  sockets; never infer availability from text in a chat response.
- `development-link`: open a ready HTTP service through the official Runner
  transport and an isolated HTTPS origin.
- `hot-update`: forward HTTP assets and WebSocket text/binary frames for HMR.
- `revocation`: enforce the original login, membership, session owner, endpoint
  identity, expiry, explicit revocation, and release incarnation on access.

## How to get to it (user POV)

1. Open a session you own and start its development service, for example
   `pnpm dev --host 0.0.0.0`. Open **会话预览** and find the actual ready port.
2. Choose **打开开发预览** and allow the popup. The reusable URL contains no
   credential. Keep the app's development server running in that session.
3. Edit the app's source. A framework with HMR, such as Vite, updates the opened
   page over WebSocket; preview itself does not add HMR to a static file server.
4. Choose **停止预览**. The old URL is denied and active sockets close. If the
   service already stopped, use **撤销预览链接**. Logging out also denies access.

## Driving it with an owned environment

`tests/saas/test_development_preview_browser.py` starts actual Vite processes,
HTTPS listeners, the production gateway composition, real SaaS password/cookie
authentication, official conversation/permission stores, and the actual React
control. It verifies anonymous/non-owner denial, credential-free handoff, HMR
with retained input, socket closure, revocation, and logout. Run:

```sh
uv run pytest -q tests/saas/test_development_preview_browser.py \
  tests/saas/test_tenant_sandbox.py::test_concurrent_background_launches_keep_distinct_tenant_identity \
  --basetemp=/absolute/owned-evidence-directory
```

Install the locked web dependencies and Chromium first. Screenshots, video, and
redacted network observations are written outside the checkout. Accounts and
keys are isolated fixtures. The Runner routing seam points to a real private
listener; official tunnel frame behavior has separate regression coverage.
This local test is not signed-image or production acceptance.

The generic `verify-env` app can verify official Server-to-Runner discovery from
a real session terminal. It has no SaaS preview gateway unless that composition
is explicitly configured, so it must report the gateway as unavailable.

## Release and operations

The feature defaults to disabled. A release enabling it needs all of:

- The exact `dp1a00000001` control-plane migration, following `lm2t00000001`.
  PostgreSQL 16 and 18 inventory/security catalog pins include all six capability
  profiles. The RLS inventory adds exactly one table, bringing the count to 132.
- A canonical `development_preview_root_domain` in the reviewed public release
  specification, separate from the primary and static-preview domains. The
  renderer requires the migration and emits only the two corresponding settings.
- A dedicated 32–4096 byte `development-preview-key` in the existing application
  keys Secret. The init container copies it with mode `0400`; configure both
  `OMNIGENT_SAAS_DEVELOPMENT_PREVIEW_ROOT_DOMAIN` and
  `OMNIGENT_SAAS_DEVELOPMENT_PREVIEW_KEY_FILE`. Missing paired configuration fails
  startup. Never reuse the main authentication signing key.
- Wildcard DNS and TLS for `*.ROOT_DOMAIN`, and reviewed ingress forwarding to
  the SaaS Server with WebSocket upgrades. Keep Host/Origin intact and redact
  cookies, authorization, and POST bodies from logs. No direct public Runner or
  development port is needed.
- The `runner` capability, admitted Runner fleet, and exact main image's normal
  signing, supply-chain, compatibility, restore, rollback and rollout gates.
  A local passing migration is not production admission.

Grants are persisted as hashes and scoped context, not plaintext credentials.
Handoffs are POST-only, origin-bound, single-use, and expire within 60 seconds.
Preview cookies are host-only, Secure, HttpOnly and SameSite Strict. Access
expires within one hour or the original login's expiry. New release incarnations
reject old grants even if the database is restored. Turning the feature off does
not delete retained grant records; downgrade refuses to drop a populated table.
Application rollback therefore needs an explicitly qualified schema-compatible
image or the reviewed restore procedure.

## Boundaries and troubleshooting

- Discovery accepts loopback/all-interface HTTP listeners owned by at most 256
  session processes, returning at most 16 services. POSIX Shell helpers own a
  kernel session so a background server remains discoverable after its immediate
  shell exits. A deliberately detached process that leaves that session is not
  claimed. Closing the environment stops its owned process group.
- TLS-only local services, Unix sockets, external IP listeners, services requiring
  platform cookies, and non-HTTP protocols are not preview targets. A listening
  port with an unhealthy HTTP response cannot be opened as ready.
- Stopping or replacing the owning process invalidates its opaque endpoint.
  Reopen from the refreshed service list after restarting a service or Runner.
- Upstream app cookies and main SaaS credentials are not forwarded. Apps needing
  external origins, OAuth redirects, or their own login cookies need a separately
  designed integration; do not relax this gateway's origin policy to hide failure.
- A configured gateway without working wildcard routing is not ready for users.
  Production acceptance must open the same admitted image through real DNS/TLS,
  authenticated ownership and Runner transport, then repeat HMR, stop, logout,
  cross-user denial and rollback checks.
