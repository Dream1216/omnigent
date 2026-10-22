# Production SLO and capacity evidence

This directory intentionally contains no qualifying evidence. Only immutable,
exact-revision `production_slo_capacity_observation` records from the approved
workflow belong here. CI timings, local benchmarks, a green health endpoint, a
single replica, or an isolated load test without a production observation window do
not satisfy the contract.

Records must contain no raw Tenant identity or customer payload. Store only bounded
metrics, hashes, immutable evidence references and storage-lock receipts, and
independently attested facts. Symbolic links are forbidden.
