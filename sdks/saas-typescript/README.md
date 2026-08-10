# Omnigent SaaS TypeScript SDK

This dependency-free SDK targets only the isolated `/api/v1` SaaS surface and
does not modify the official Omnigent SDK.

```ts
import { OmnigentSaasClient } from "@omnigent/saas-client";

const client = new OmnigentSaasClient({
  baseUrl: "https://api.example.com",
  apiKey: "omk_...",
  timeoutMs: 20_000,
});

const run = await client.createRun(
  "018f2f2a-1ee4-7d0d-9e61-49f9a23fc001",
  { title: "Review", input: { prompt: "Review this change" } },
  { idempotencyKey: "review-change-142" },
);
```

Cursors are opaque and must be passed back unchanged. `cancelRun` and
`retryRun` require the latest `etag` plus an idempotency key. The SDK does not
implicitly retry mutations.
