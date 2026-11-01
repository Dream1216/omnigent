# Casdoor identity state synchronization

The private identity ingress and state application services are in development.
Do not enable them in production until the release-bound worker, controlled HTTPS
ingress, source qualification, lag alerts and end-to-end acceptance are complete.

## Authority and durable state

`IdentityConnection` remains the canonical link to one stable Global User.
`saas_identity_provider_states` separately records active, disabled or deleted
provider state. Provider deletion is terminal for automatic reconciliation.
Neither notifications nor provider snapshots may restore a locally revoked
connection or a suspended/deleted product user, change credential authority,
create a tenant or grant a product role.

`saas_identity_event_inbox` stores normalized, namespace-bound locator digests,
stable provider event names and processing receipts. It does not store raw audit
objects, credentials, user names or email addresses. Altered reuse of an event
name is rejected. The ingress returns HTTP 200 only after the receipt commits;
the pinned Casdoor Webhook worker does not accept other 2xx statuses as success.

Notifications trigger a fresh fixed-subject read. An event's actor and desired
flags are not the identity authority. An event arriving before its first cache
mapping stays retryable so that a transient security change is not discarded.
Unknown mappings eventually retain a dead-letter receipt for investigation.

## Claims, account locks and sessions

Claims and application lock Global User, canonical connection, then provider
state. The durable claim digest pins the connection, namespace, user security
version, contact snapshot, token and deadline. Provider HTTP requests run outside
these transactions. Application rechecks the full claim and current time after
acquiring locks. An expired worker or a result obtained before an intervening
account/connection change cannot commit.

Confirmed state, contact-verification or password revision changes invalidate
local sessions and advance the existing subject OIDC fence. An old callback
therefore cannot create a valid session after synchronization. The first read
also checks the provider's password-change time. The password revision is a
domain-separated metadata digest that distinguishes same-second resets; no
password hash or salt is retained in the sync tables.

Observed disabled/deleted identities are excluded from login, provision, link,
reauthentication, session issue, verified invitation contact, backup sign-in
methods and credential cutover. A fresh offline-authorized reconnection can
resolve a disabled cache after provider readback, but cannot reactivate a
provider-deleted cache. Recovery alone does not restore the old identity.

Read failures remain operational failures. They do not imply deletion or revoke
otherwise valid sessions. Periodic claims include missing caches and due active
or disabled connections, with intervals/backoff bounded at 60 seconds. An actual
worker and admitted load must still prove the five-minute convergence target.

## Release and restore requirements

- Use a separately authenticated controlled HTTPS ingress, a rotating private
  Header keyring and bounded requests. Forwarded protocol headers and browser
  cookies alone do not authenticate this channel.
- Give the worker only its verified authenticator database login, public IdP
  pins, release receipt and independently qualified read-only provider authority.
  The local provider drills use an owned migration credential; those drills do
  not qualify the production provider credential's write restrictions.
- Verify the exact serving revision, subject fences, worker source/image and
  paired schema receipt before enabling processing. Follow the credential
  migration runbook's replica-drain requirements for older serving revisions.
- Keep worker availability and lag separate from product runtime readiness.
  Alert on dead letters, readback failure and convergence lag above 300 seconds;
  prove the limit with the admitted identity population and request budgets.
- Include both new tables in the matched product/IdP/key restore. Once either
  table contains records, database downgrade is rejected; use application
  rollback while preserving the expanded schema and receipts.
- Qualify every PostgreSQL 16/18 role profile independently. Never copy a
  predecessor catalog digest or treat a discovery candidate as approval.

## Developer verification

Run from the repository root using the checkout's environment:

```sh
PYTHONPATH=. python -m pytest -q tests/saas/test_identity_sync.py \
  tests/saas/test_identity_sync_credential_fences.py \
  tests/saas/test_identity_inbox.py tests/saas/test_identity_events_http.py
```

With `OMNIGENT_SAAS_TEST_POSTGRES_URL` pointing to a disposable test cluster, run:

```sh
PYTHONPATH=. python -m pytest -q tests/saas/test_identity_sync_postgresql.py \
  tests/saas/test_identity_sync_migration.py
```

Repeat the PostgreSQL tests on both supported majors. They use isolated
databases and independent NOBYPASSRLS authenticator logins. Human acceptance
must additionally sign in through real OIDC, mutate the same owned IdP account,
observe old sessions fail within five minutes, then verify a permitted fresh
sign-in and unchanged workspace roles. Local test assertions and fixture-driven
ticks do not replace that complete ingress/worker/browser acceptance.
