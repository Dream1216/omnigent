# ADR-006: SLO, data class, RPO, RTO, and recovery

- Decision status: Accepted architecture
- Production approval: Governed by `../baseline.json` and bound by `../adr-approval-candidate.json`
- Technical owner: `site-reliability`

## Context

Availability, durability, and recovery promises must be measurable at the
service and data-class boundary. A backup job or healthy replica is not proof
that a tenant, region, encryption key revision, or exact application schema can
be restored within a contracted objective.

## Decision

Adopt the service catalog, SLOs, error-budget actions, and T0-T2 data classes in
`baseline.json`. T0 targets RPO no more than 5 minutes and RTO no more than 60
minutes; T1 targets RPO no more than 15 minutes and RTO no more than 240 minutes;
T2 restores from the latest acknowledged durable checkpoint with RTO no more
than 480 minutes. Product and SRE must separately approve these business terms.

Backups are encrypted, protected from application deletion, separated across
failure domains, and periodically restored into an isolated environment before
validation. Tenant-scoped and regional drills run at least quarterly and bind
source, schema, adapter, image, key, and data revisions. Error-budget exhaustion
halts feature and upstream promotion according to the recorded action.

## Consequences and rollback

No SLO or recovery objective is advertised until dashboards and drills exist.
Rollback uses a schema-compatible signed image and verified restore point; it
does not claim recovery based on an untested backup catalog entry.

## Acceptance evidence

- Active dashboards calculate each SLI from production telemetry.
- Multi-AZ failover, PITR, isolated restore, tenant restore, and region loss are timed.
- Restored RLS, audit, billing, identity, bindings, and deletion state are verified.
- Two consecutive drills meet objectives with signed evidence and remediation owners.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent SRE Review is claimed.
SLO measurement and recovery verification gates remain mandatory.

SRE confirms monitoring, paging, backup ownership, failure-domain independence,
measured objectives, drill cadence, and recovery escalation.
