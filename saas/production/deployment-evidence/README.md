# Production deployment and failure-domain evidence

This directory intentionally contains no qualifying evidence. Only immutable,
exact-revision policy-matched schema-v2/v3 `production_deployment_drill` records produced against
the release candidate in the production deployment belong here.

A Kubernetes Node object, a zone label, multiple Pods, or a healthy endpoint does not
prove independent failure domains. Every record must bind Pods to distinct physical
host identities in at least two zones, prove replica/PDB/topology-spread and hardened
container facts for every required component, exercise the complete containment and
failure matrix, prove the exact Runner database controls (target-database-only,
no create/temporary authority, catalog-drift rejection, and RPC/trigger-enforced
transitions), reference a DSSE-authenticated immutable artifact, and carry
distinct SRE, security, and release-engineering attestations.

Do not copy local Kind output, screenshots, raw node names, cluster IDs, customer IDs,
repository paths, credentials, or self-authored boolean-only reports into this
directory. Identifiers in records are SHA-256 values; detailed raw probe output stays
in the access-controlled immutable artifact.

V2 retains the original RuntimeDefault-only contract. V3 requires the exact
reviewed Runner-only Localhost profile and one complete node/Pod/container/image,
node-file metadata/hash, effective-profile/runtime/process/time/raw-evidence
observation per Runner placement. A Node label, Seccomp=2 or an arbitrary JSON
claim cannot substitute for Root's actual node/CRI/probe capture. Init and all
other components remain RuntimeDefault. No record is automatically converted;
current exact source and the existing independent whole-file signatures are
required. The external actual collector is a separate reviewed prerequisite.

V3 pins `containerd://2.3.2-k3s2` and rejects unknown/invalid kernels and reused
container IDs or raw-evidence hashes across Runner placements. Runtime changes
require a new profile capture/review; no compatibility is inferred.
