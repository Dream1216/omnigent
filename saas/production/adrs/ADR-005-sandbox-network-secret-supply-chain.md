# ADR-005: Sandbox, network, secret, and supply-chain policy

- Status: Accepted under sole-owner risk waiver
- Technical owner: `security`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Repositories, dependencies, prompts, generated commands, browser content, and
tool output are hostile inputs. Process separation alone does not prevent host
escape, metadata access, secret theft, DNS rebinding, cache poisoning, or the
promotion of an untrusted build artifact.

## Decision

Each Run executes as a non-privileged identity in an isolated writable layer
with bounded CPU, memory, processes, disk, inode, and time. It receives no host
container socket, control-plane credential, database credential, or unrestricted
filesystem mount. Network policy defaults to deny internal, loopback, link-local,
metadata, private, control-plane, and cross-tenant destinations; every redirect
and DNS resolution is re-evaluated through the egress authority.

Tools are authorized server-side. Secrets are redeemed through short-lived,
Run/Tool/resource-bound capabilities and are not persisted in environment
snapshots, logs, diffs, caches, or artifacts. Production uses immutable image
digests, locked dependencies, SBOM, provenance, signature verification,
vulnerability and license policy, and a reproducible-build comparison.

## Consequences and rollback

Some repositories and tools require explicit egress or capability grants.
Emergency rollback selects a previously admitted signed digest; it never falls
back to a mutable tag or disables admission controls.

## Acceptance evidence

- Host escape, socket, device, namespace, and sibling-sandbox probes are blocked.
- SSRF, redirect, DNS rebinding, metadata, and direct-TCP bypass tests are blocking.
- Secret canaries do not appear in logs, artifacts, snapshots, or child processes.
- Unsigned, stale-scan, critical-vulnerability, and non-reproducible images fail.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent security Review is
claimed. Production verification gates remain mandatory.

Security confirms threat coverage, exception ownership, secret lifecycle,
supply-chain admission, incident response, and signed rollback artifacts.
