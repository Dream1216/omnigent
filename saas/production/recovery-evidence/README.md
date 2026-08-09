# Production recovery evidence

Only immutable evidence from an actual production-like tenant or cluster
recovery drill belongs in this directory. CI fixtures, local dumps, screenshots,
operator assertions, and backup-job success records are not recovery evidence.

Every JSON record is validated against `../recovery-policy.json`. It must bind
the exact upstream, adapter, schema, and product revisions; prove encrypted and
deletion-protected backup material in another failure domain; restore into an
isolated account, network, key, object prefix, search index, and Runner pool;
record measured RPO/RTO; pass every RLS, tombstone, revocation, binding, ledger,
object, key, and canary check; reference a signed immutable artifact; and carry
the required independent attestations.

The verifier deliberately reports production `blocked` while the directory has
no current qualifying tenant and cluster records. Do not add synthetic evidence
to change that result.
