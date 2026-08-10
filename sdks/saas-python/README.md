# Omnigent SaaS Python SDK

This package targets only the isolated `/api/v1` SaaS surface. It does not
import, wrap, or change the official Omnigent Python client.

```python
from omnigent_saas_client import OmnigentSaasClient, RunCreate

with OmnigentSaasClient(
    base_url="https://api.example.com",
    api_key="omk_...",
    timeout=20,
) as client:
    run = client.create_run(
        "018f2f2a-1ee4-7d0d-9e61-49f9a23fc001",
        RunCreate(title="Review", input={"prompt": "Review this change"}),
        idempotency_key="review-change-142",
    )
    events = client.list_run_events(run.project_id, run.id)
```

Collection cursors are opaque: pass `page.next_cursor` back unchanged. Mutating
an existing Run requires both an `Idempotency-Key` and the latest weak ETag.
Configure finite connect/read/write/pool timeouts; the SDK never retries a
mutation implicitly.
