import {
  ApiError,
  ApiTimeoutError,
  AuthenticationError,
  AuthorizationError,
  ConflictError,
  NotFoundError,
  PreconditionFailedError,
  ProtocolError,
  RateLimitError,
  TransportError,
  ValidationError,
  type ApiErrorOptions,
} from "./errors.js";
import type {
  ListProjectsOptions,
  ListRunEventsOptions,
  ListRunsOptions,
  MutationOptions,
  Page,
  Project,
  Run,
  RunContent,
  RunCreate,
  RunEvent,
  RunRetry,
  VersionedMutationOptions,
} from "./types.js";

export const SDK_VERSION = "0.1.0";
const weakEtag = /^W\/"[1-9][0-9]*"$/;
const localHosts = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export interface OmnigentSaasClientOptions {
  baseUrl: string;
  apiKey: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
  allowInsecureLocalhost?: boolean;
}

type QueryValue = string | number | undefined;

function validateBaseUrl(value: string, allowInsecureLocalhost: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new TypeError("baseUrl must be an absolute HTTP(S) URL", { cause: error });
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("baseUrl cannot contain credentials, query, or fragment");
  }
  if (url.protocol !== "https:" && !(allowInsecureLocalhost && localHosts.has(url.hostname))) {
    throw new TypeError("baseUrl must use HTTPS except for explicit local development");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TypeError("baseUrl must be an absolute HTTP(S) URL");
  }
  return url.toString().replace(/\/$/, "");
}

function identifier(value: string, field: string): string {
  const cleaned = value.trim();
  if (!cleaned || cleaned.includes("/") || cleaned.length > 128) {
    throw new TypeError(`${field} is invalid`);
  }
  return encodeURIComponent(cleaned);
}

function idempotencyKey(value: string): string {
  if (!value || value.length > 128 || value.trim() !== value) {
    throw new TypeError("idempotencyKey must contain 1 to 128 trimmed characters");
  }
  return value;
}

function ifMatch(value: string): string {
  if (!weakEtag.test(value)) {
    throw new TypeError('ifMatch must be a weak version ETag such as W/"3"');
  }
  return value;
}

function pageLimit(value: number | undefined, fallback: number, maximum: number): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < 1 || resolved > maximum) {
    throw new TypeError(`limit must be between 1 and ${maximum}`);
  }
  return resolved;
}

function opaqueCursor(value: string | undefined): string | undefined {
  if (value !== undefined && (!value || value.length > 4096)) {
    throw new TypeError("cursor is invalid");
  }
  return value;
}

function query(entries: Array<[string, QueryValue]>): string {
  const params = new URLSearchParams();
  for (const [name, value] of entries) {
    if (value !== undefined) params.append(name, String(value));
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

function record(value: unknown, context: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProtocolError(`${context} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function page<T>(value: unknown, context: string): Page<T> {
  const payload = record(value, context);
  if (!Array.isArray(payload.items)) throw new ProtocolError(`${context}.items must be an array`);
  if (payload.next_cursor !== null && typeof payload.next_cursor !== "string") {
    throw new ProtocolError(`${context}.next_cursor must be a string or null`);
  }
  return { items: payload.items as T[], next_cursor: payload.next_cursor };
}

export class OmnigentSaasClient {
  readonly #baseUrl: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;
  readonly #authorization: string;

  constructor(options: OmnigentSaasClientOptions) {
    if (!options.apiKey || options.apiKey.length > 4096) throw new TypeError("apiKey is invalid");
    const timeoutMs = options.timeoutMs ?? 30_000;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000) {
      throw new TypeError("timeoutMs must be between zero and 300000 milliseconds");
    }
    this.#baseUrl = validateBaseUrl(
      options.baseUrl,
      options.allowInsecureLocalhost ?? false,
    );
    this.#timeoutMs = timeoutMs;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#authorization = `Bearer ${options.apiKey}`;
  }

  toString(): string {
    return `OmnigentSaasClient(baseUrl=${JSON.stringify(this.#baseUrl)}, apiKey=<redacted>)`;
  }

  async listProjects(options: ListProjectsOptions = {}): Promise<Page<Project>> {
    const payload = await this.#request(
      "GET",
      `/api/v1/projects${query([
        ["limit", pageLimit(options.limit, 50, 100)],
        ["cursor", opaqueCursor(options.cursor)],
        ["status", options.status],
      ])}`,
      [200],
    );
    return page<Project>(payload, "project page");
  }

  async getProject(projectId: string): Promise<Project> {
    return record(
      await this.#request("GET", `/api/v1/projects/${identifier(projectId, "projectId")}`, [200]),
      "project",
    ) as unknown as Project;
  }

  async createRun(
    projectId: string,
    request: RunCreate,
    options: MutationOptions,
  ): Promise<Run> {
    return record(
      await this.#request(
        "POST",
        `/api/v1/projects/${identifier(projectId, "projectId")}/runs`,
        [201],
        request,
        { "Idempotency-Key": idempotencyKey(options.idempotencyKey) },
      ),
      "run",
    ) as unknown as Run;
  }

  async listRuns(projectId: string, options: ListRunsOptions = {}): Promise<Page<Run>> {
    const values: Array<[string, QueryValue]> = [
      ["limit", pageLimit(options.limit, 50, 100)],
      ["cursor", opaqueCursor(options.cursor)],
      ["created_after", options.createdAfter],
      ["created_before", options.createdBefore],
    ];
    for (const status of options.status ?? []) values.push(["status", status]);
    const payload = await this.#request(
      "GET",
      `/api/v1/projects/${identifier(projectId, "projectId")}/runs${query(values)}`,
      [200],
    );
    return page<Run>(payload, "run page");
  }

  async getRun(projectId: string, runId: string): Promise<Run> {
    return record(
      await this.#request("GET", this.#runPath(projectId, runId), [200]),
      "run",
    ) as unknown as Run;
  }

  async getRunContent(projectId: string, runId: string): Promise<RunContent> {
    return record(
      await this.#request("GET", `${this.#runPath(projectId, runId)}/content`, [200]),
      "run content",
    ) as unknown as RunContent;
  }

  async cancelRun(
    projectId: string,
    runId: string,
    options: VersionedMutationOptions & { reason?: string | null },
  ): Promise<Run> {
    return record(
      await this.#request(
        "POST",
        `${this.#runPath(projectId, runId)}/cancel`,
        [200],
        { reason: options.reason ?? null },
        {
          "Idempotency-Key": idempotencyKey(options.idempotencyKey),
          "If-Match": ifMatch(options.ifMatch),
        },
      ),
      "run",
    ) as unknown as Run;
  }

  async retryRun(
    projectId: string,
    runId: string,
    request: RunRetry,
    options: VersionedMutationOptions,
  ): Promise<Run> {
    return record(
      await this.#request(
        "POST",
        `${this.#runPath(projectId, runId)}/retry`,
        [201],
        request,
        {
          "Idempotency-Key": idempotencyKey(options.idempotencyKey),
          "If-Match": ifMatch(options.ifMatch),
        },
      ),
      "run",
    ) as unknown as Run;
  }

  async listRunEvents(
    projectId: string,
    runId: string,
    options: ListRunEventsOptions = {},
  ): Promise<Page<RunEvent>> {
    if (
      options.afterSequence !== undefined &&
      (!Number.isInteger(options.afterSequence) || options.afterSequence < 0)
    ) {
      throw new TypeError("afterSequence must be a non-negative integer");
    }
    const payload = await this.#request(
      "GET",
      `${this.#runPath(projectId, runId)}/events${query([
        ["limit", pageLimit(options.limit, 100, 500)],
        ["cursor", opaqueCursor(options.cursor)],
        ["after_sequence", options.afterSequence],
      ])}`,
      [200],
    );
    return page<RunEvent>(payload, "run event page");
  }

  #runPath(projectId: string, runId: string): string {
    return (
      `/api/v1/projects/${identifier(projectId, "projectId")}/runs/` +
      identifier(runId, "runId")
    );
  }

  async #request(
    method: string,
    path: string,
    expected: number[],
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    let response: Response;
    try {
      response = await this.#fetch(`${this.#baseUrl}${path}`, {
        method,
        redirect: "error",
        signal: controller.signal,
        headers: {
          Authorization: this.#authorization,
          Accept: "application/json",
          "User-Agent": `omnigent-saas-typescript/${SDK_VERSION}`,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...extraHeaders,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch (error) {
      if (controller.signal.aborted) throw new ApiTimeoutError("public API request timed out");
      throw new TransportError("public API transport failed", { cause: error });
    } finally {
      clearTimeout(timeout);
    }
    const text = await response.text();
    let payload: unknown = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch (error) {
        if (expected.includes(response.status)) {
          throw new ProtocolError("public API returned non-JSON success response", {
            cause: error,
          });
        }
      }
    }
    if (!expected.includes(response.status)) this.#raiseApiError(response, payload);
    return payload;
  }

  #raiseApiError(response: Response, payload: unknown): never {
    const envelope = typeof payload === "object" && payload !== null ? payload : {};
    const rawError = "error" in envelope ? (envelope as { error?: unknown }).error : undefined;
    const error =
      typeof rawError === "object" && rawError !== null
        ? (rawError as Record<string, unknown>)
        : {};
    const options: ApiErrorOptions = {
      statusCode: response.status,
      code: typeof error.code === "string" ? error.code : "http_error",
      message:
        typeof error.message === "string"
          ? error.message
          : `public API returned HTTP ${response.status}`,
      requestId:
        typeof error.request_id === "string"
          ? error.request_id
          : response.headers.get("X-Request-Id"),
      details:
        typeof error.details === "object" && error.details !== null
          ? (error.details as Record<string, unknown>)
          : {},
      retryAfter: response.headers.get("Retry-After"),
    };
    const ErrorType =
      new Map<number, typeof ApiError>([
        [401, AuthenticationError],
        [403, AuthorizationError],
        [404, NotFoundError],
        [409, ConflictError],
        [412, PreconditionFailedError],
        [422, ValidationError],
        [429, RateLimitError],
      ]).get(response.status) ?? ApiError;
    throw new ErrorType(options);
  }
}
