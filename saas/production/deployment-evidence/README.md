# Production deployment and failure-domain evidence

This directory intentionally contains no qualifying evidence. Only immutable,
exact-revision `production_deployment_drill` records produced against the release
candidate in the production deployment belong here.

A Kubernetes Node object, a zone label, multiple Pods, or a healthy endpoint does not
prove independent failure domains. Every record must bind Pods to distinct physical
host identities in at least two zones, prove replica/PDB/topology-spread and hardened
container facts for every required component, exercise the complete containment and
failure matrix, reference a DSSE-authenticated immutable artifact, and carry distinct
SRE, security, and release-engineering attestations.

Do not copy local Kind output, screenshots, raw node names, cluster IDs, customer IDs,
repository paths, credentials, or self-authored boolean-only reports into this
directory. Identifiers in records are SHA-256 values; detailed raw probe output stays
in the access-controlled immutable artifact.
