# Commercial SaaS compatibility support

The production compatibility promise covers the active signed downstream
release and one previous signed downstream release (N-1). An upstream release
tag is not a production rollback target merely because it passes a smoke test.

The N-1 Server and Host must each be selected by an immutable OCI digest built
from `Dream1216/omnigent` main by the protected SaaS image workflow. Before
admission, verify their signatures, provenance, source revisions, image labels,
current control-plane schema and adapter contracts, and the security acceptance
suite from the current candidate revision. Record its completion before the
rollback exercise and retain the receipt hash. The security exercise includes
Staff and Tenant authorization, RLS, cross-tenant rejection, Runner/Preview
containment, and a real model turn.
Preserve the exact evidence digests. The N-1 images remain unselected until
these checks pass for the same pair of Server and Host images.

The historical `Backwards-Compat` workflow exercises upstream tags. Its
failures remain visible and any repository-level required check remains in
force until changed through separate governance. Its result does not certify
commercial SaaS support, nor can its latest-tag smoke result authorize a
production rollback.
Upstream tags `v0.2.0` through `v0.13.0` are outside the production support
matrix; the observed `v0.13.0` server permits an edit collaborator to execute
an owner Host shell under the current test contract. The pinned `p0s3` N-1
compatibility image also predates the current `p0s14` schema and is not a
current release rollback target.

After image admission, observe the current candidate by digest in the
production canary for at least 3,600 seconds. Exercise rollback to the
independently verified N-1 digest pair within 900 seconds. Both images must
recover with the current database schema, tenant isolation, and security
controls intact. Record distinct release-engineering, security, and
site-reliability approvals after the exercise. A healthy service or a
diagnostic compatibility run alone never makes the release ready.

Release-policy schema version 3 and release-evidence version 3 are required
for this support boundary. Older version 2 evidence cannot be reused as a
production admission receipt under the new contract.
