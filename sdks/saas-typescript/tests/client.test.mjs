import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiTimeoutError,
  OmnigentSaasClient,
  PreconditionFailedError,
  RateLimitError,
} from "../dist/index.js";

const projectId = "018f2f2a-1ee4-7d0d-9e61-49f9a23fc001";
const runId = "018f2f2a-1ee4-7d0d-9e61-49f9a23fc002";
const project = {
  id: projectId,
  space_id: "018f2f2a-1ee4-7d0d-9e61-49f9a23fc003",
  name: "Automation",
  visibility: "private",
  status: "active",
  authorization_version: 4,
  created_at: "2026-08-10T01:00:00Z",
  updated_at: "2026-08-10T02:00:00Z",
  etag: 'W/"4"',
};
const run = {
  id: runId,
  project_id: projectId,
  task_id: "018f2f2a-1ee4-7d0d-9e61-49f9a23fc004",
  session_id: null,
  parent_run_id: null,
  status: "queued",
  version: 2,
  event_sequence: 2,
  queue_class: "interactive",
  priority: 0,
  metadata: { client: "test" },
  created_at: "2026-08-10T01:00:00Z",
  updated_at: "2026-08-10T01:00:01Z",
  terminal_at: null,
  etag: 'W/"2"',
};
const content = {
  run_id: runId,
  input: { prompt: "private" },
  product_revision: "product-sha",
  upstream_revision: "upstream-sha",
  schema_revision: "pc6",
  adapter_contract_version: "v1",
  etag: 'W/"2"',
};

function response(status, body, headers = {}) {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function client(fetch) {
  return new OmnigentSaasClient({
    baseUrl: "http://localhost:8765",
    apiKey: "omk_not-logged",
    timeoutMs: 1_000,
    allowInsecureLocalhost: true,
    fetch,
  });
}

test("project metadata and events use opaque cursors without content leakage", async () => {
  const calls = [];
  const api = client(async (url, init) => {
    calls.push({ url: String(url), init });
    const path = new URL(String(url)).pathname;
    if (path.endsWith("/events")) {
      return response(200, {
        items: [
          {
            id: "event-1",
            run_id: runId,
            sequence: 3,
            type: "run.queued",
            data: { status: "queued" },
            trace_id: "trace-1",
            created_at: "2026-08-10T01:00:01Z",
          },
        ],
        next_cursor: "event.next",
      });
    }
    if (path === `/api/v1/projects/${projectId}`) return response(200, project);
    return response(200, { items: [project], next_cursor: "project.next" });
  });

  const projects = await api.listProjects({ limit: 10, cursor: "project.prior", status: "active" });
  const selected = await api.getProject(projectId);
  const events = await api.listRunEvents(projectId, runId, {
    limit: 25,
    cursor: "event.prior",
    afterSequence: 2,
  });

  assert.equal(projects.next_cursor, "project.next");
  assert.equal(selected.name, "Automation");
  assert.equal("input" in selected, false);
  assert.equal(events.items[0].sequence, 3);
  assert.equal(events.next_cursor, "event.next");
  assert.equal(
    calls[0].url,
    "http://localhost:8765/api/v1/projects?limit=10&cursor=project.prior&status=active",
  );
  assert.equal(
    calls[2].url,
    `http://localhost:8765/api/v1/projects/${projectId}/runs/${runId}/events?limit=25&cursor=event.prior&after_sequence=2`,
  );
  assert.equal(calls[0].init.headers.Authorization, "Bearer omk_not-logged");
  assert.equal(api.toString().includes("omk_not-logged"), false);
});

test("run mutations carry idempotency and ETag while content stays explicit", async () => {
  const calls = [];
  const api = client(async (url, init) => {
    calls.push({ url: String(url), init });
    const path = new URL(String(url)).pathname;
    if (path.endsWith("/content")) return response(200, content);
    if (path.endsWith("/runs") || path.endsWith("/retry")) return response(201, run);
    return response(200, run);
  });

  await api.createRun(
    projectId,
    { title: "Review", input: { prompt: "secret" } },
    { idempotencyKey: "create-42" },
  );
  await api.cancelRun(projectId, runId, {
    idempotencyKey: "cancel-42",
    ifMatch: 'W/"2"',
    reason: "operator request",
  });
  await api.retryRun(
    projectId,
    runId,
    { priority: 10 },
    { idempotencyKey: "retry-42", ifMatch: 'W/"2"' },
  );
  const privateContent = await api.getRunContent(projectId, runId);

  assert.deepEqual(privateContent.input, { prompt: "private" });
  assert.equal(calls[0].init.headers["Idempotency-Key"], "create-42");
  assert.equal("If-Match" in calls[0].init.headers, false);
  assert.equal(calls[1].init.headers["Idempotency-Key"], "cancel-42");
  assert.equal(calls[1].init.headers["If-Match"], 'W/"2"');
  assert.equal(calls[2].init.headers["Idempotency-Key"], "retry-42");
  assert.equal(calls[2].init.headers["If-Match"], 'W/"2"');
  assert.match(calls[3].url, /\/content$/);
});

test("typed errors preserve request IDs and Retry-After", async () => {
  const stale = client(async () =>
    response(
      412,
      {
        error: {
          code: "etag_mismatch",
          message: "resource changed",
          request_id: "req-body",
          details: { current_etag: 'W/"3"' },
        },
      },
      { "X-Request-Id": "req-header" },
    ),
  );
  await assert.rejects(
    stale.cancelRun(projectId, runId, {
      idempotencyKey: "cancel-stale",
      ifMatch: 'W/"2"',
    }),
    (error) => {
      assert.ok(error instanceof PreconditionFailedError);
      assert.equal(error.code, "etag_mismatch");
      assert.equal(error.requestId, "req-body");
      return true;
    },
  );

  const limited = client(async () => response(429, null, { "Retry-After": "7" }));
  await assert.rejects(limited.listProjects(), (error) => {
    assert.ok(error instanceof RateLimitError);
    assert.equal(error.retryAfter, "7");
    return true;
  });
});

test("finite timeout and local ETag validation fail closed", async () => {
  const timed = new OmnigentSaasClient({
    baseUrl: "http://localhost:8765",
    apiKey: "omk_test",
    timeoutMs: 5,
    allowInsecureLocalhost: true,
    fetch: async (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      }),
  });
  await assert.rejects(timed.getRun(projectId, runId), ApiTimeoutError);
  const api = client(async () => response(200, run));
  await assert.rejects(
    api.cancelRun(projectId, runId, {
      idempotencyKey: "cancel-invalid",
      ifMatch: "2",
    }),
    /weak version ETag/,
  );
  await assert.rejects(api.listRuns(projectId, { limit: 101 }), /between 1 and 100/);
  await assert.rejects(
    api.listRunEvents(projectId, runId, { afterSequence: -1 }),
    /non-negative integer/,
  );
});
