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

## How to get to it (user POV)

- Open the customer sign-in or create-account page directly.
- In the main app, open Settings and choose Sign-in methods.
- In customer project management or the delivery workspace, choose unified
  sign-in, or Sign-in methods in the header. The sign-in return retains the page.
- Complete provider authorization to reach the completion or conflict page.
- On Sign-in methods, confirm connecting an identity, sign in again, or sign out.

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
- Customer console legacy workflows: `tests/saas/test_project_admin_browser.py`
  and `tests/saas/test_delivery_browser.py`.
- Signed protocol, replay and logout races: `tests/saas/test_oidc_http_auth.py`,
  `tests/saas/test_oidc_logout.py`, and
  `tests/saas/test_federated_sessions_postgresql.py`.
- For a real provider preview, first encounter an email conflict without an
  automatic merge, sign in to the old account, explicitly connect the identity,
  and confirm the account ID stays stable. Reauthenticate in a second tab and
  start a connection from the first. Sign out through the product; check the
  provider directly notified the product and matching sessions are revoked.

## Gotchas

- Staff authentication, host credentials and Databricks sign-in are separate.
- A captured notification replay is not proof of direct provider connectivity.
- Browser API fixtures prove the actual packaged UI, not provider availability.
- PostgreSQL role/race tests and isolated SQLite previews do not qualify a
  production schema, TLS setup, HA deployment, tenant setup or release rollback.
- Pending email conflicts never prove ownership. Public conflict approval is
  rejected; use fresh local and provider proof through the connection page.
- Capture screenshots outside Git. Record the entry point and pair each UI
  result with authoritative, read-only API or database counts.
