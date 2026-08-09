# ADR-009: Single-region production boundary

- Status: Accepted under sole-owner risk waiver
- Technical owner: `product-owner`
- Candidate: `omnigent-saas-p0-2026-08-09`

## Context

Multi-AZ availability within one region does not provide active-active
multi-region service, sovereign isolation, or automatic cross-border failover.
Product language, contracts, routing, backups, and operational procedures must
not imply capabilities that the first production deployment does not provide.

## Decision

The first production offer is single-region, multi-AZ. The tenant selects one
supported home region at provisioning time. Control-plane authority, runtime
placement, primary data, and protected backups remain within the disclosed
regional policy unless a separately approved transfer is executed. Dedicated
Placement is an explicit commercial option and does not imply multi-region.

No active-active, automatic regional failover, sovereign cloud, or universal
data-residency promise is made. A future multi-region offer requires a new ADR,
conflict-resolution model, identity and key design, routing and failover model,
commercial terms, privacy review, and measured regional recovery gate.

## Consequences and rollback

A regional outage may exceed ordinary availability until recovery completes.
Tenant-facing UI, order forms, support responses, status pages, and contracts
must state this boundary. Rollback remains within the selected region and uses
verified multi-AZ or isolated recovery material.

## Acceptance evidence

- Product terms, region selector, routing, manifests, backups, and status text agree.
- Cross-region placement and backup creation are denied without approved policy.
- Multi-AZ failure and regional recovery drills match the disclosed objectives.
- Dedicated Placement responsibility and limits are visible before purchase.

## Owner confirmation

Governance downgrade: repository Owner `Dream1216` assumes this technical-owner
decision under `sole-owner-risk-waiver`; no independent product Review is
claimed. Production verification gates remain mandatory.

The Product Owner confirms offer language, supported regions, residency,
dedicated-placement terms, outage expectations, and absence of multi-region claims.
