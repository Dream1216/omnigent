# SaaS customer authentication

Customers sign in through the configured identity provider or a legacy password
during transition. Connecting another identity preserves the account and requires
explicit consent and fresh authentication. Product permissions remain local.

## Sub-features

- `entry-mode`: legacy, dual and central-only login, loading and unavailable states.
- `signup`: central registration before product workspace setup.
- `completion`: original callback, locale, safe return path and storage failure.
- `connect`: connected identities, pending conflict, consent and fresh proof.
- `reauthenticate`: current-account proof and cross-tab CSRF refresh.
- `logout`: local revocation followed by provider logout and back-channel convergence.
- `workspace-setup`: authenticated users without a workspace, name-only creation,
  pending/recovery/support states, invitations and multiple workspace choices.
- `workspace-selection`: choose a server-provided workspace for browser and
  WebSocket requests; removed membership requires another authorized choice.
- `credential-migration`: staged import, explicit per-user authority cutover,
  stable account/resources, and old-password rejection after cutover.
- `credential-recovery`: offline authorization for a fresh password, with session
  and provider connection revocation and an immutable migration receipt.

## How to get to it (user POV)

- Open the customer sign-in or create-account page directly.
- In the main app, open Settings and choose Sign-in methods.
- In customer project management or the delivery workspace, choose unified
  sign-in, or Sign-in methods in the header. The sign-in return retains the page.
- Complete provider authorization to reach the completion or conflict page.
- On Sign-in methods, confirm connecting an identity, sign in again, or sign out.
- After sign-in without an available workspace, continue to workspace setup.
- Open workspace setup directly, or choose Workspaces in the main app Settings.
- On setup, choose an available workspace, create another, resume a previous
  request, or enter an invitation code.

## Driving it with the repro environment

Preconditions: use an owned, isolated SaaS preview with synthetic identities and
build the actual login export first. These SaaS tests own their servers; they
do not use the main app runner from [Verify Omnigent](skills/verify-omnigent/SKILL.md).

- Direct login/signup, modes, callbacks, conflicts, connection consent, mobile,
  cross-tab storage, unavailable IdP, and both console entry points:
  `tests/saas/test_identity_ui_browser.py` and
  `tests/saas/test_oidc_browser_entry.py`.
- Existing password/registration pages and language layout:
  `tests/saas/test_onboarding_ui_browser.py`.
- Main Settings entry: `web/src/pages/SettingsPage.test.tsx`.
- Setup direct entry, Chinese/English draft preservation, mobile and desktop,
  network retry/reload, pending recovery, invitations, signed-out state and
  unavailable browser storage: `tests/saas/test_workspace_setup_browser.py`.
- Authenticated creation, repeat requests, quota, multiple tenants and shared
  opening workflow: `tests/saas/test_workspace_creation.py`.
- Workspace preference, HTTP/WebSocket routing, CSRF and membership removal:
  `tests/saas/test_active_workspace_scope.py`.
- Real database worker authority, concurrent replay, source backfill and
  non-bypass-owner rollback guards: `tests/saas/test_workspace_creation_postgresql.py`,
  `tests/saas/test_workspace_creation_migration.py`, and
  `tests/saas/test_federated_sessions_postgresql.py`.
- Both registration and authenticated-intent paths through Billing, Runtime,
  Project, Activation and first Run admission:
  `tests/saas/test_onboarding_postgresql.py`.
- Customer console legacy workflows: `tests/saas/test_project_admin_browser.py`
  and `tests/saas/test_delivery_browser.py`.
- Signed protocol, replay and logout races: `tests/saas/test_oidc_http_auth.py`,
  `tests/saas/test_oidc_logout.py`, and
  `tests/saas/test_federated_sessions_postgresql.py`.
- Credential import, interrupted commit/retry, source changes and pending identity
  fences: `tests/saas/test_credential_migration.py`,
  `tests/saas/test_casdoor_credential_import.py`, and
  `tests/saas/test_credential_migration_postgresql.py`.
- Private bounded batches and fresh-password authorization:
  `tests/saas/test_credential_migration_cli.py` and
  `tests/saas/test_credential_recovery.py`. Use the synthetic procedure in
  `saas/production/casdoor/CREDENTIAL_MIGRATION.md`; it requires owned IdP and
  database fixtures and never grants production authorization by itself.
- On the password HTTP entry, confirm an imported user can still sign in before
  cutover, is rejected after cutover, and another unmigrated user can still sign
  in. An existing session must expire on cutover. Confirm a pending imported
  identity cannot create a second account after a source email change.
- For a real provider preview, first encounter an email conflict without an
  automatic merge, sign in to the old account, explicitly connect the identity,
  and confirm the account ID stays stable. Reauthenticate in a second tab and
  start a connection from the first. Sign out through the product; check the
  provider directly notified the product and matching sessions are revoked.
- For the new-user runtime journey, register through the provider's email code,
  create a workspace on setup, and check its default project exists in the
  official runtime. Configure the owned Host with its allocated workspace route,
  execute a task through the main composer, and read back the completed assistant
  item. Sign out, verify a protected endpoint returns 401 and CSRF storage is
  cleared, then sign back in and verify the same account, project and task.

## Gotchas

- Staff authentication, host credentials and Databricks sign-in are separate.
- A captured notification replay is not proof of direct provider connectivity.
- Browser API fixtures prove the actual packaged UI, not provider availability.
- A persisted workspace choice grants no permission; each request still checks
  current membership and allocation. Explicit scope requests retain their own choice.
- Runtime adapter fixtures prove Saga integration and control-plane Run admission;
  they do not prove a real runner executed a user's first task.
- An official native runtime session and a canonical control-plane Run are
  separate records. A completed native assistant item does not by itself mark
  the onboarding Saga complete or prove managed-Run scheduling and metering.
- PostgreSQL role/race tests and isolated SQLite previews do not qualify a
  production schema, TLS setup, HA deployment, tenant setup or release rollback.
- Pending email conflicts never prove ownership. Public conflict approval is
  rejected; use fresh local and provider proof through the connection page.
- An import receipt grants no login before its identity connection is committed.
  Restoring retained hashes does not restore password authority. Recovery must
  install a different password and does not change the deployment's login mode.
- Capture screenshots outside Git. Record the entry point and pair each UI
  result with authoritative, read-only API or database counts.
