# Enterprise IdP SCIM E2E and evidence admission

This runbook closes provider interoperability only with real, revision-bound external
evidence. Local mock IdPs, protocol unit tests and screenshots do not qualify as an
Entra, Okta or Google Workspace acceptance.

## Preconditions

- Deploy one exact product revision to a publicly reachable TLS endpoint. Bind every
  request and evidence record to that 40-character revision.
- Create an isolated production-like tenant and a separate SCIM Directory credential
  for each provider. Never reuse a bearer token across providers.
- Store provider credentials only in the provider and approved secret manager. Do not
  write bearer tokens, raw email addresses, phone numbers or addresses into GitHub
  artifacts.
- Record provider tenant, application, subject and acceptance identities only as
  SHA-256 values. Store raw provisioning logs in an access-controlled immutable
  `s3://`, `gs://`, `az://` or `oci://` bundle.

## Microsoft Entra

Use a non-gallery enterprise application with the Omnigent SCIM base URL and Directory
token. Run **Test Connection**, configure User and Group mappings, then run on-demand
provisioning followed by a scheduled synchronization cycle. The accepted evidence must
cover user and group creation, multi-valued email/phone/address mappings, attribute and
scope drift, suspension/deprovisioning, attempted resurrection and token rotation.

Reference: <https://learn.microsoft.com/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups>

## Okta

Use a private SCIM 2.0 integration in an isolated Okta org. Run the provider CRUD suite,
assign a user and group, push the group, update optional and multi-valued attributes,
deactivate/reactivate, remove assignment and rotate the Directory token. Capture the
provider test/run identity and the matching immutable Omnigent operation receipts.

References:

- <https://developer.okta.com/docs/guides/scim-provisioning-integration-connect/main/>
- <https://developer.okta.com/docs/guides/scim-provisioning-integration-test/main/>

## Google Workspace constraint and accepted paths

Google Workspace automatic provisioning is offered for supported catalog integrations;
an arbitrary custom SAML application does not receive a generic outbound SCIM
configuration surface. Therefore a direct test cannot be claimed merely by selecting
`google_workspace` in Omnigent.

One of these externally approved paths is required:

1. Omnigent is admitted as a supported Google Workspace auto-provisioning integration;
   run the catalog integration against the exact revision.
2. An approved broker or Google Admin SDK Directory connector performs the sync; record
   the broker/connector revision and prove the same tenant, user, group, suspension,
   restoration and no-resurrection outcomes end to end.

The evidence must name which path was used. A local SCIM client labelled “Google” is not
Google Workspace evidence.

Google supported-app guidance: <https://support.google.com/a/topic/10018788>

## Required evidence and admission

Create a `production_enterprise_acceptance` JSON record under
`saas/production/enterprise-evidence/` following `enterprise-policy.json`. It must contain
separate integration facts and positive operation counts for Microsoft Entra, Okta and
Google Workspace. Four distinct roles (`identity-owner`, `security`, `privacy`, and
`customer-admin`) attest the exact product revision. The DSSE subject digest must match
the immutable evidence bundle.

Commit evidence only on `main`, then dispatch **SaaS enterprise IdP admission** with the
exact product revision. The job runs only in the protected `production-evidence`
environment and fails closed until all provider facts, customer acceptance and
attestations qualify.

This admission does not replace signed Wheel/image publication, canary deployment,
N-1 rollback or the final production Receipt.
