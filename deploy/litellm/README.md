# LiteLLM managed model storage verification

The SaaS control plane owns approved model definitions and provider credentials.
LiteLLM holds a derived runtime copy. The trusted model verification Worker can
compare that copy with the immutable draft and canonical credential before and
after a bounded test. It returns only non-secret binding and ciphertext-state
evidence. This does not publish a model or prove that every serving replica has
loaded the database state.

## Locked storage contract

Use the source and image digests in `saas/production/litellm_release.json` and the
MIT core image built by this directory's Dockerfile. The storage reader targets
LiteLLM 1.105.1 and its `aes-256-gcm` writer. For a new dedicated LiteLLM database,
set these base settings before creating any credentials:

```yaml
model_list: []
general_settings:
  store_model_in_db: true
  encryption_algorithm: aes-256-gcm
```

Supply LiteLLM with a separate, deployment-managed `LITELLM_SALT_KEY`. Mount the
same value as a restricted file in the trusted Worker. Do not fall back to the
master key, commit either key, or expose them to the browser or Agent. The SaaS
`SecretCipher` remains the canonical credential authority; this profile only
controls the derived LiteLLM copy.

Legacy XSalsa20, plaintext, corrupt ciphertext and unknown formats are rejected.
For an existing database, validate a supported migration and restore procedure
before enabling this reader. Changing the salt is not a migration. Back up the
database and the matching salt using the existing encrypted recovery workflow.

The reader checks the exact model ID, alias, provider, endpoint, named credential,
disabled retry/override fields and hidden credential value. It rejects unapproved
database configuration overlays. The locked server's unmodified empty
`auto_router_tuning_baseline_v3` license baseline is allowed; nonempty or unknown
rows are not. Do not remove licensing records to make verification pass.

## Dedicated read identity

Provision only in the separate LiteLLM logical database, never the SaaS database.
After the pinned vendor migration, the existing principal operator applies
`postgresql_attestation_principals.sql`; the dedicated LiteLLM database owner
applies `postgresql_attestation_grants.sql`. For example, using deployment-owned
PostgreSQL service definitions:

```sh
psql "service=litellm-principal-operator" -X -v ON_ERROR_STOP=1 \
  -f deploy/litellm/postgresql_attestation_principals.sql
psql "service=litellm-database-owner" -X -v ON_ERROR_STOP=1 \
  -v litellm_database=omnigent_litellm \
  -f deploy/litellm/postgresql_attestation_grants.sql
```

Replace the example database name with the validated dedicated database name.
The grants script revokes PUBLIC temporary-table access in that database; review
other clients first. It grants only the required columns in
`LiteLLM_ProxyModelTable`, `LiteLLM_CredentialsTable` and `LiteLLM_Config`.
It does not grant access to inference keys, spend logs or SaaS tables.

Issue the `omnigent_litellm_attestor` password through the deployment secret
workflow, not a checked-in SQL literal or command-line argument. Its only role
membership is `omnigent_litellm_attestation_read`, with INHERIT true and SET/ADMIN
false. It cannot create databases or roles, bypass RLS, write application data,
or assume the base role. Startup checks reject additional readable public
columns, write privileges, elevated capabilities and unexpected membership.

## Worker configuration and rollout

The feature is disabled by default. The trusted Outbox Worker needs the existing
projection and verification configuration, current control-plane migration
receipt and separate Projection/Billing service logins. In addition, configure:

| Setting | Required value |
| --- | --- |
| `OMNIGENT_SAAS_MODEL_PROJECTION_ENABLED` | `true` |
| `OMNIGENT_SAAS_MODEL_VERIFICATION_ENABLED` | `true` |
| `OMNIGENT_SAAS_MODEL_CONFIG_ATTESTATION_ENABLED` | `true` |
| `OMNIGENT_SAAS_LITELLM_ATTESTATION_DATABASE_URL_FILE` | Absolute path to the dedicated read-login DSN file |
| `OMNIGENT_SAAS_LITELLM_SALT_KEY_FILE` | Absolute path to the matching salt file |

Use regular owner-only files with mode `0400`; the production DSN loader also
requires the existing TLS/CA contract. Direct secret environment values are not
an alternative. The attestation DSN must use the exact read login and a database
different from the SaaS database. Do not mount these files in the Web or Runner.

Deploy every new Outbox consumer before enabling Staff command admission. A
mixed consumer deployment must not claim new model operations. Disabled
attestation preserves older test-receipt compatibility, but that is not a
publication approval: publishing must require fresh configuration evidence and
separate serving-replica readiness.

Before sending a test, storage drift rejects the operation without reserving
budget or contacting the provider. Drift detected after a response fails
verification while retaining and settling actual usage. Delivery recovery only
reconciles the original receipt and budget; it does not send inference again.
Disabling the feature does not erase receipts, release uncertain charges or
replay a user task.

## Replica route readiness

`LiteLLMReplicaReadinessAuthority` checks a deployment-owned inventory of two to
sixteen individual replica endpoints. Never build this inventory from browser
input or substitute a shared load-balancer address. The library reads the
canonical stored credential before and after concurrent `GET /model/info`
checks. In the locked version, that endpoint lists the process's router model
list. Every configured endpoint must expose the approved immutable deployment,
model, endpoint, named credential and disabled retry settings.

The result binds the draft, credential version, stored-state fingerprint and
exact endpoint inventory. It is valid for at most thirty seconds from the start
of the check. A publisher must recheck it against the current inventory and
authorization immediately before changing the release pointer. Missing routes,
endpoint failures, changed storage or expired evidence reject readiness; sibling
reads are cancelled before returning. These checks do not issue inference keys,
perform inference, reserve budget or grant publication authority.

The evidence scope is
`stored_credentials_and_visible_replica_routes_not_hidden_replica_memory`.
It proves neither hidden credential bytes in each process nor physical Kubernetes
membership. Production publication still needs a trusted deployed-fleet inventory,
the approved protocol/capability evidence, tenant authorization and release gates.
Constructing the library does not enable production routing.

The isolated fixture freezes periodic reload at 3600 seconds to make a stale
second replica deterministic. It adds a model to the primary, checks that the
second replica prevents readiness, reloads that replica and checks again. This
is test configuration, not a production reload recommendation; production uses
its separately reviewed reload and topology settings.

## Verification and recovery

Run the focused regression from the repository root:

```sh
.venv/bin/python -m pytest -q \
  tests/saas/test_litellm_configuration_attestation.py \
  tests/saas/test_litellm_replica_readiness.py \
  tests/saas/test_model_verification_worker.py \
  tests/saas/test_production_model_projection.py
```

The `LiteLLM isolated contracts` workflow additionally runs actual LiteLLM and
PostgreSQL on native amd64 and arm64. It verifies the read identity, hidden
override rejection, wrong-key rejection and restored database state, using a
synthetic upstream and no production credentials. A passing component report
must state `masked_credentials_attested=true`, the explicit storage-only scope,
successful cleanup and `production_traffic_changed=false`. Replica checks also
require `replica_route_readiness_checked=true` and the explicit route-readiness
scope above. Their provider-request counter must remain unchanged.

During an isolated restore, restore both the database and matching salt, reapply
the reviewed read-role grants to the restored logical database, and validate the
identity before comparing the original bindings. Confirm that wrong credentials
and hidden overrides still fail. Then independently verify serving replicas,
real provider behavior and the production release gates. A matching database
fingerprint alone is not evidence that the running fleet is safe to publish.
