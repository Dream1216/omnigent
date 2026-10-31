# Casdoor customer identity integration

This branch implements the first protocol and browser-session slice of the
Casdoor integration plan dated 2026-10-13. It is not ready for production
cutover. Existing customer and Staff authentication remain on their current
production deployment.

## Configuration

The server accepts `OMNIGENT_SAAS_AUTH_MODE=legacy|dual|casdoor`. Without any
Casdoor files, `legacy` preserves the existing composition. Other modes require
all three files; partial configuration fails before serving requests. The
mode value is currently a configuration contract; entry routing and the
per-user credential authority gates must be completed before enabling it.

- `OMNIGENT_SAAS_CASDOOR_CONFIG_FILE`: an owner-controlled JSON file matching
  [config.example.json](config.example.json).
- `OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE`: owner-only UTF-8 client secret,
  at least 16 bytes; one trailing line ending is accepted.
- `OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE`: owner-only, exactly 32 binary bytes,
  identical on all replicas. No line ending is removed from this binary key.

Only one customer application and one ordinary identity organization are
accepted. Endpoints are derived from the pinned HTTPS origin and application.
The backend accepts only RS256, validates the identity owner, and uses either
Basic client authentication or explicit form client authentication. It never
mixes both methods. Casdoor's supported `language=zh|en` query parameter is
used rather than assuming `ui_locales` affects its UI.

## Implemented behavior

`GET /saas/auth/oidc/casdoor/start` accepts `intent=login|signup`, `return_to`
and `ui_locale=zh-CN|en-US`. The return target, locale, encrypted PKCE verifier,
state and nonce survive a replica change. Distinct browser-binding cookies
allow simultaneous login transactions in two tabs. Linking requires a recent
local session, CSRF, `prompt=login`, `max_age=0`, and a fresh IdP `auth_time`.

For a browser callback, the original response delivers a CSP-protected,
non-cacheable document and same-origin scripts. They store the local CSRF
token and replace the current history entry. No provider token or client
secret is delivered to browser storage. Storage failure leaves a retry link.
`GET /saas/auth/bootstrap` reports the next step without exposing a CSRF
secret. A user without available scopes is sent to `/setup`.

Customer management, delivery and notification pages share the same browser
session helper. Each mutation reads the current shared token, so another
tab's login does not leave an old CSRF value captured at page load. Staff
notification CSRF continues to use its separate key.

Migration `cd1a00000001` expands existing OIDC transactions and preserves their
RLS policies and grants. Empty test schemas can be downgraded; retained
transactions require application-only rollback. Production migration receipt
and catalog anchors must still be generated through the existing release
replay, never by bypassing the schema verifier.

## Verification

From this checkout, with its Python development and SaaS dependencies:

```bash
PYTHONPATH=. python -m pytest tests/saas/test_oidc_http_auth.py tests/saas/test_casdoor_config.py tests/saas/test_oidc_completion_browser.py -q
OMNIGENT_SAAS_TEST_POSTGRES_URL=postgresql+psycopg://USER@localhost/TEST_ADMIN_DB PYTHONPATH=. python -m pytest tests/saas/test_casdoor_migration.py -q
```

The PostgreSQL fixture creates and removes a disposable database. Use a local
test cluster; the fixture installs the repository's test role graph.

Manual acceptance on a fully assembled preview: start two login tabs,
complete both callbacks, refresh, and open customer management in a new tab.
Perform a permitted mutation, then sign in again in another tab and repeat
the mutation in the original management tab. Disable both storage backends
and confirm the callback shows a retry instead of claiming success.

## Required work before cutover

- Production PostgreSQL 16/18 migration replay, exact catalog anchors,
  role graph receipts, runtime verification and restore compatibility.
- Transaction-key rotation with old keys retained for in-flight transactions.
- Authenticated workspace creation intent, shared onboarding Saga, historical
  backfill, RLS, `/setup`, invitations and first Run acceptance.
- Per-user credential ownership and migration receipts; old passwords must
  stop working after authority moves to Casdoor.
- External-session association, RP and back-channel logout, durable identity
  event Inbox, state reconciliation and disable/reset convergence.
- Explicit account-linking and conflict pages, full branding, actual language
  switching without resending codes, signup expiration and replay tests.
- Approved social/enterprise channels, isolated deployment with durable DB,
  production TLS and email, signed images, GitOps rollout and recovery drills.
