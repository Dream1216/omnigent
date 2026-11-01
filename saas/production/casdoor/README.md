# Casdoor customer identity integration

This branch implements protocol, browser sessions and authenticated workspace
setup from the Casdoor integration plan dated 2026-10-13. It is not ready for production
cutover. Existing customer and Staff authentication remain on their current
production deployment.

## Configuration

The server accepts `OMNIGENT_SAAS_AUTH_MODE=legacy|dual|casdoor`. Without any
Casdoor files, `legacy` preserves the existing composition. Other modes require
all three files; partial configuration fails before serving requests.
`/saas/auth/options` publishes local entry paths and the mode without secrets.
`dual` offers both password and central sign-in; `casdoor` hides customer password
forms and rejects local password login and new legacy registration requests.
Already-issued legacy registration verification remains available. Per-user
credential authority and migration gates are still required before cutover.

- `OMNIGENT_SAAS_CASDOOR_CONFIG_FILE`: an owner-controlled JSON file matching
  [config.example.json](config.example.json).
- `OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE`: owner-only UTF-8 client secret,
  at least 16 bytes; one trailing line ending is accepted.
- `OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE`: owner-only, either exactly 32
  binary bytes or a versioned JSON keyring, identical on all replicas. No line
  ending is removed from a binary key. A keyring has `schema_version: 1`, an
  `active_key_id` and a `keys` object containing base64-encoded 32-byte keys.
  Retain the `legacy` key when moving from binary configuration. A replica
  refuses startup if an unexpired transaction needs a removed key. Deploy
  overlapping keyrings to every replica before changing the active key.

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
`reauthenticate=true` requires the same fresh IdP proof and, when already signed
in, an identity connected to the current user. The authorizing local session
is checked again under a row lock before linking and before session issuance.
Session issuance locks logout fences before the parent session, matching
back-channel revocation so concurrent reauthentication cannot deadlock.
The public conflict decision API cannot approve a link; the user must confirm
in `/saas/account/identities` and complete a fresh identity authorization.

For a browser callback, the original response delivers a CSP-protected,
non-cacheable document and same-origin scripts. They store the local CSRF
token and replace the current history entry. No provider token or client
secret is delivered to browser storage. Storage failure leaves a retry link.
`GET /saas/auth/bootstrap` reports the next step without exposing a CSRF
secret. A user without available scopes is sent to `/setup`.

`/setup` offers existing workspaces, invitation acceptance, and a name-only
creation form using the reviewed plan and region defaults. An authenticated
user may create multiple independent intents. Cookie authentication, CSRF,
actor-scoped idempotency and a per-user daily quota guard creation. The browser
retains the request key across an uncertain network outcome and resumes the
accepted intent by URL. Opening a workspace stores a preference in the local
session; HTTP and WebSocket requests still recheck live membership, placement
and allocation. Settings provides a Workspaces entry to change that preference.

Customer management, delivery and notification pages share the same browser
session helper. Each mutation reads the current shared token, so another
tab's login does not leave an old CSRF value captured at page load. Staff
notification CSRF continues to use its separate key.

Migration `cd1a00000001` expands existing OIDC transactions and preserves their
RLS policies and grants. Empty test schemas can be downgraded; retained
transactions require application-only rollback. Production migration receipts
must be generated through the existing release replay and checked against
source-pinned catalog anchors, never by bypassing the schema verifier.

Migration `cd1b00000001` associates local sessions with verified provider,
issuer, subject, optional `sid` and ID Token issue time. Signed back-channel
notifications revoke matching external sessions; legacy and Staff sessions
are outside their scope. Persistent event receipts reject conflicting replay,
and PostgreSQL row locks prevent a late callback from restoring a logged-out
session. New credentials issued after the logout epoch remain usable.

Migration `cd1c00000001` persists reauthentication and its authorizing local
session. Retained older link transactions remain stored but cannot complete
without a bound session. Its downgrade refuses retained OIDC transactions,
including for a schema owner subject to forced RLS. Full production catalog
qualification uses the combined `cd3a00000001` head; the intermediate Casdoor
heads are not separately qualified deployment targets. Recovery replay remains
required before cutover.

Migration `cd3a00000001` adds per-user credential authority and immutable
hash-only migration receipts. The private worker stages verified Argon2id
imports and explicitly switches authority without changing account or business
resource IDs. Retained local hashes cannot authenticate after cutover. Pending
imports cannot create a replacement product account, even if the source email
changes. Fresh-password recovery requires a bounded offline Ed25519 grant;
the online worker has public verification keys only. See
[the migration runbook](CREDENTIAL_MIGRATION.md) for configuration, bounded
batches, crash retries, key rotation and controlled recovery.

Migration `cd2a00000001` adds `TenantCreationIntent` without a unique user
constraint, backfills verified registration history, and connects both request
sources to the same Billing → Runtime → Project → Activation Saga. Legacy
registration/Saga paths remain readable during deployment overlap. New RLS
and column grants keep HTTP creation under `saas_authenticator`, Saga writes
under `saas_onboarding`, and status projection under its narrow role. The
same migration adds the session's optional tenant/space preference. Retained
intents or workspace selections require application-only rollback.
The current server requires this schema head. Deploy the matching Worker
before accepting new intents. An old Worker does not understand authenticated
intent events; stop new creation and drain or quarantine that event generation
before rolling the Worker back.

Clean PG16/18 source replay provides separate catalog anchors for the exact
15/17/18/19-service graphs and for reviewed Preview deployment policies. The
candidate workflow runs all eight combinations. To reproduce one, select
`OMNIGENT_SAAS_REPLAY_ROLE_PROFILE=core|model|admin|projection` and run
`tests/saas/test_production_migration_replay.py` against a fresh dedicated
cluster via `OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL`. The default profile
is `admin`. Each run must start from a fresh cluster. Current-head admission
does not qualify a predecessor image, backup restore, or a production release.

Local logout revokes the product session before returning a fixed provider
logout URL. Provider unavailability cannot undo that revocation. Logout JWTs
require RS256, issuer, audience, `iat`, `exp`, `jti`, the logout event and a
subject or `sid`; a login nonce is forbidden. Unknown signing keys trigger
at most one forced refresh per five seconds per provider.

## Pinned Casdoor candidate

[source-lock.json](source-lock.json) fixes the upstream source archive and
patch checksums. The maintained patch adds the required five-minute expiry
to logout JWTs and selects a validated `language` query parameter before
i18n initialization. The unpatched v4.25.0 logout JWT lacks `exp` and is
rejected by this verifier. See the
[back-channel logout specification](https://openid.net/specs/openid-connect-backchannel-1_0.html).

Prepare the source with `python -m saas.scripts.prepare_casdoor_source
--output /tmp/casdoor-source`. The candidate workflow builds the patched
frontend and server using pinned image digests and uploads an amd64 Docker
archive, checksum and source receipt. Its non-root runtime requires mounted
configuration and writable `/data` and `/logs`. This workflow neither
publishes nor qualifies an image for production; real protocol acceptance,
signing and the normal release admission remain required.

## Verification

Email and SMS registration take priority over additional social and enterprise
providers. Use one required `Email or Phone` signup item with `rule=Normal`, a
random hidden ID, hidden username, password and confirmation. Each selected
address requires its own verification code. Configure both delivery providers
before exposing the choice; do not require customers to supply both addresses.

The `stbz.2` patch preserves email-as-username for email registrations and uses
the generated ID for phone-only accounts. It also enforces the combined required
contact in the server validator; a client hiding the input cannot create an
account without either address. Native Go regression cases run in the image
build. A new patched image still needs real signup, resend/expiry/replay and
signed OIDC acceptance before activation.

The `stbz.3` patch stores the exact canonical phone that passed the native signup
or signed-in contact-change OTP check. Standard JWTs, userinfo and authenticated
user readback derive verification from that stored binding. A parseable number,
administrator JSON, batch import or syncer metadata cannot create the binding.
Changing the number or country clears incompatible proof; changing back cannot
revive it. Unrelated updates preserve existing proof. The internal binding is
excluded from JSON and generic user-field writes. Native Go checks cover real
SQLite persistence, forged metadata, contact changes and token claims.

The added `verified_phone` database column starts empty for existing accounts;
do not backfill it from number presence. Database backups must include it.
JSON exports intentionally omit it, so imported accounts need a fresh OTP proof.
Qualify the schema change on the production database engine and exercise the
new image's real signup and change paths before activation.

The `stbz.4` patch returns `phoneE164` with `phoneVerified` on authenticated
readback, deriving both from the stored binding. This lets the product reader
consume the exact canonical address without guessing country prefixes.
Password-only sign-in remains the initial SMS account policy. A phone OTP alone
cannot authorize password recovery, including through a repurposed contact code.
Email recovery requires the currently verified email, a one-time code and a
five-minute server session proof; an email change or expired proof rejects the
reset. Signed-in password changes still require the current password. Phone-only users
without that password need the controlled support recovery procedure.

The product requests the phone scope, validates canonical signed assertions and
stores phone ownership on the existing issuer/subject connection. Creating a
workspace with a phone also requires a completed, active authoritative readback
from the pinned Casdoor reader. A new account waits for that check; retrying
preserves its workspace request. Contact changes revoke sessions through the
existing worker fences. The private reader protocol is version 2; replace reader
and worker processes together with their exact source pins before activation.
Email invitations still require a verified email. A phone never merges users or
supplies a fictitious email. Account erasure clears the phone fields; the privacy
executor can erase these fields but cannot grant ownership.

The `cd4b00000001` extension starts old connections with no phone proof and
retains the existing RLS and email registration column grants. Retained phone
data blocks destructive downgrade; use an application rollback. Review and pin
fresh PG16/18 catalogs for all four authority profiles, then pass the strict
migration lane before deployment. The Casdoor candidate workflow's manual
`discover_source_catalogs` option collects review candidates only. Its catalogs
cannot serve as production acceptance or update release anchors automatically.

The `cd4c00000001` workspace INSERT policy requires an active account and a
verified email or authoritative Casdoor phone baseline at the database boundary.
Unverified, unchecked, disabled or deleted phone identities cannot create intents.
The actor, source, registration and status constraints still apply to both paths.
Downgrading preserves existing intents and restores the prior email-only check.
Stop new workspace admission and drain writers before rolling the policy back;
the previous application cannot admit phone creation against that policy.

Real delivery, number recycling, the full signup-to-first-Run journey and the
new provider's live HTTP recovery/readback paths still require acceptance.

From this checkout, with its Python development and SaaS dependencies:

```bash
PYTHONPATH=. python -m pytest tests/saas/test_oidc_http_auth.py tests/saas/test_oidc_logout.py tests/saas/test_oidc_key_rotation.py tests/saas/test_casdoor_config.py tests/saas/test_oidc_completion_browser.py -q
PYTHONPATH=. python -m pytest tests/saas/test_oidc_browser_entry.py tests/saas/test_identity_ui_browser.py -q
PYTHONPATH=. python -m pytest tests/saas/test_workspace_creation.py tests/saas/test_active_workspace_scope.py tests/saas/test_workspace_setup_browser.py -q
OMNIGENT_SAAS_TEST_POSTGRES_URL=postgresql+psycopg://USER@localhost/TEST_ADMIN_DB PYTHONPATH=. python -m pytest tests/saas/test_casdoor_migration.py tests/saas/test_federated_sessions_postgresql.py -q
OMNIGENT_SAAS_TEST_POSTGRES_URL=postgresql+psycopg://USER@localhost/TEST_ADMIN_DB PYTHONPATH=. python -m pytest tests/saas/test_workspace_creation_postgresql.py tests/saas/test_workspace_creation_migration.py -q
```

The PostgreSQL fixture creates and removes a disposable database. Use a local
test cluster; the fixture installs the repository's test role graph.

Manual acceptance on a fully assembled preview: start two login tabs,
complete both callbacks, refresh, and open customer management in a new tab.
Perform a permitted mutation, then sign in again in another tab and repeat
the mutation in the original management tab. Disable both storage backends
and confirm the callback shows a retry instead of claiming success.
With a new verified identity, confirm setup requests only a workspace name,
retry an interrupted request, and confirm it produces one workspace. Open it,
create another through Settings, switch between both, and accept an invitation
to a third. Remove the selected membership and confirm access is denied until
another authorized workspace is chosen. Execute the first task using a real
runner; control-plane admission with a fixture adapter does not satisfy that check.

## Required work before cutover

- Release-specific PostgreSQL role graph receipts, runtime verification,
  predecessor-image compatibility and backup restore qualification.
- Fully assembled provider → setup → workspace → real runner first-task
  acceptance, including retry and membership revocation.
- Production qualification of per-user migration batches and offline recovery
  authorization, including old-password rejection after authority changes.
- Durable identity event Inbox, state reconciliation and disable/reset convergence.
- Approved social/enterprise channels, isolated deployment with durable DB,
  production TLS and email, signed images, GitOps rollout and recovery drills.
