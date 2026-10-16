# Platform managed model candidates

The independent Staff console manages encrypted connections, immutable model drafts, platform-funded test budgets, bounded verification, and tenant-scoped candidate publication versions. Recording a candidate catalog does not enable runtime routing or change the customer model selector. Connections, verification, and publication have separate, default-off capability flags.

## Sub-features

- `connection-admission`: create a candidate connection and append a credential version without displaying a stored key.
- `operation-recovery`: recover the original durable operation after a lost response or reload, without creating a new command.
- `deployment-draft`: select the current acknowledged credential and append an immutable model definition; projection success still means not tested and not published.
- `test-funding`: configure explicit platform-funded monetary, token, and attempt limits without borrowing a customer identity or enabling a model.
- `funding-recovery`: preserve unsaved inputs after an uncertain save, stop further writes, and read the saved policy before continuing.
- `bounded-verification`: explicitly confirm a potentially paid single-attempt test with an enforced output limit; inspect protocol usage and financial recovery without publishing the model.
- `verification-recovery`: recover a lost admission response under the original opaque command reference; an uncertain supplier response remains unknown rather than zero-cost or an instruction to log into a CLI.
- `tenant-publication`: select and inspect one tenant scope, confirm a verified model and expected catalog generation, and inspect the immutable publication receipt; runtime remains disabled.
- `publication-recovery`: recover the original publication after a lost response or reload without submitting another command or sending inference.
- `staff-authority`: a current fresh Staff operator can mutate; a security auditor can read but cannot edit.
- `small-screen`: the same console entry remains usable on a narrow viewport without horizontal overflow.

## How to get to it (user POV)

- Open `/platform-admin`, authenticate in the independent Staff realm, then select the managed-model connections navigation item. The page contains connection creation, credential rotation, operation receipts, model drafts, test funding, verification, and tenant candidate catalogs when their capabilities are configured. Start a test from its draft row; inspect the latest receipt from the same row or refresh the current command. For publication, inspect the target tenant catalog, start a new independent command, then confirm publication from the verified draft row.
- Open `/platform-admin#model-connections` after Staff authentication, including after a page reload. This reaches the same view directly.
- Use either route on desktop or mobile. The Tenant Owner Beta model-provider console is a separate legacy entry, not an alternative Staff login.

## Driving it with the repro environment

Preconditions: these Staff console tests own their HTTPS server, disposable SQLite database, Staff identities, browser contexts, and synthetic projection endpoint. They do not use the general server/Runner repro instance, real provider credentials, or production data. Chromium from this checkout's Playwright installation must be available. Set `OMNIGENT_SAAS_BROWSER_EVIDENCE_DIR` to a directory outside the tracked tree to capture screenshots.

- Connection creation, rotation, navigation, reload recovery, readonly auditor, and mobile: `tests/saas/test_platform_admin_browser.py::test_real_chromium_model_connections_and_lost_receipt_recovery`.
- Draft selection, pending credential rejection, lost receipt recovery, unchanged public model ID, readonly auditor, and mobile: `tests/saas/test_platform_admin_browser.py::test_real_chromium_model_draft_projection_and_lost_receipt_recovery`.
- Funding configuration, exact monetary units, lost receipt recovery, direct-view reload, readonly auditor, and mobile: `tests/saas/test_platform_admin_browser.py::test_real_chromium_platform_test_funding_and_lost_receipt_recovery`.
- Bounded verification, cost confirmation and cancellation, lost-response recovery, explicit unknown costs, readonly receipt inspection, direct-view reload, and mobile: `tests/saas/test_platform_admin_browser.py::test_real_chromium_model_verification_recovery_cost_and_readonly_receipt`.
- Tenant scope, publication confirmation and cancellation, lost-response/reload recovery, readonly catalog, disabled runtime, and mobile: `tests/saas/test_platform_admin_browser.py::test_real_chromium_tenant_model_publication_lost_receipt_and_readonly_catalog`.
- Independent realm, navigation, and role/page/action boundaries: `tests/saas/test_platform_admin_browser.py::test_real_chromium_platform_console_role_page_and_action_matrix`.

Run the selected test directly with `.venv/bin/pytest -q`. Each journey drives the visible controls and cross-checks the control-plane API. Real PostgreSQL budget/role checks and real LiteLLM/provider protocol checks are separate acceptance lanes, not supplied by these browser tests.

## Gotchas

- A projection receipt is not a verification receipt. Saving funding is not a paid test. An APPLIED publication records a tenant candidate catalog version, not runtime activation or full Agent capability acceptance.
- Credential inputs are cleared after submission. Only opaque operation references may survive reload in session storage; raw credentials and request bodies must not.
- After an uncertain save, read the original operation or funding policy. Do not fabricate success from a name collision or resubmit under a new idempotency key.
- A disabled capability, unavailable Staff identity, stale authentication, or missing real runtime prerequisite is unavailable, not a passed acceptance check.
- Browser projection calls use a synthetic management endpoint. Never present these screenshots as proof of real supplier billing, OIDC signing, production rollout, or end-to-end Agent availability.
- VERIFIED on the bounded test means protocol and budget settlement, not full capability acceptance, masked-credential attestation, or runtime publication. A visible configuration readback cannot attest a hidden provider key.
