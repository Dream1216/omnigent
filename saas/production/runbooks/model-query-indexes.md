# Model query index rollout

Migration `lm2r00000001` adds bounded cursor indexes, replaces the platform-test
day index with an admitted-only partial index, and grants `saas_app` only the
additional `id` and `created_at` publication columns. It changes no stored model
documents, credentials, financial counters, unique constraints, or RLS policies.
All migrations through `lm2q00000001` remain unchanged.

## Index withdrawal and query support

| Withdrawn index | Retained query support |
| --- | --- |
| `ix_model_projection_status` | Outbox consumers fetch an operation by its primary key. Credential and deployment reads use the new scoped indexes. There is no global status queue query. |
| `ix_model_run_token_run` | Root-token lookup supplies the full `(run_id, fence_token, generation)` unique key. Token ID, hash and parent lookups retain their existing unique keys. |
| `ix_model_gateway_evidence_scope` | Evidence reads supply a reservation ID and use the existing reservation/phase or reservation/budget-version unique keys. The fixed six-phase constraint bounds each reservation independently of tenant growth. |
| `ix_model_budget_test_day` | The new `(provider_id, purpose, usage_date, id)` index excludes zero-admission rejections. The query reads at most 1,001 admitted records and rejects inconsistent excess history. |

## Staging and production order

1. Inspect the target database head and actual index definitions. Do not infer
   deployment state from Git, manually stamp a revision, or treat an unexpected
   schema as the approved Q baseline.
2. In isolated PostgreSQL 16 and 18, retain the Q definitions and representative
   query plans. Apply R, project the role script, verify actual plans under the
   relevant logins, and exercise App, authenticator, Staff, projection and billing
   workflows. SQLite synthetic plans are development evidence, not this gate.
3. Verify all seven exact ascending B-tree definitions and the absence of the four
   withdrawn indexes. Reject altered predicates, ordering, uniqueness, included
   columns, expressions, collation, operator classes and forged head markers.
   Confirm cross-tenant RLS, content-free cursor failures and denied secret columns.
4. Repeatedly downgrade R to Q and upgrade back. The downgrade must restore the
   original four index definitions and remove the two added column grants without
   changing model documents, original hashes, financial state or supplier calls.
5. Submit schema, migration tests and this runbook in a standalone schema PR.
   Deploy the compatible schema before the application that uses R pagination,
   only after independent review, exact-source catalog admission and protected CI.
   This R procedure does not establish compatibility for the earlier LiteLLM
   migrations; their complete schema/application rollout remains a separate gate.
6. Apply through the approved migration/deployment process and observe query plans,
   latency, errors, RLS and billing. Keep the Q rollback available. Do not emit
   unsupported invisible-index DDL or remove additional indexes during observation.

## Rollback

Stop R-only catalog callers or first restore the reviewed Q-compatible application,
then use the managed R-to-Q downgrade. Q removes `saas_app` access to publication
`id` and `created_at`; a still-running R customer pager would otherwise fail.
Reproject the exact Q role contract and verify the restored definitions, column
permissions, tenant isolation and financial receipts. A failure must remain a
failed release gate; restoring an index is not proof of a successful application
rollback or database backup restore.

The maintained checks are `tests/saas/test_model_index_retirement.py`,
`tests/saas/test_model_page_indexes.py` and
`tests/saas/test_model_page_indexes_postgresql.py`. The existing live-login model
and billing tests remain required; metadata checks do not replace them.
