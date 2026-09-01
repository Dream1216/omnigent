import { hostFetch } from "./host";
import { clearSaasCsrf, storeSaasCsrf } from "./saasSession";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const IDEMPOTENCY_KEY_MAX_LENGTH = 128;

export interface OnboardingCatalogPlan {
  key: string;
  currency: string;
  trialDays: number;
  trialRunLimit: number;
  trialConcurrencyLimit: number;
}

export interface OnboardingCatalog {
  schemaVersion: 1;
  revision: string;
  plans: OnboardingCatalogPlan[];
  regions: string[];
  verificationTtlSeconds: number;
}

export interface OnboardingRegistrationRequest {
  email: string;
  displayName?: string | null;
  tenantName: string;
  tenantSlug: string;
  defaultSpaceName: string;
  defaultSpaceSlug: string;
  planKey: string;
  homeRegion: string;
}

export interface OnboardingRegistrationResponse {
  registrationId: string;
  status: "verification_pending";
}

export interface OnboardingVerificationResponse {
  registrationId: string;
  status: "tenant_provisioning";
  onboardingId: string;
  userId: string;
  tenantId: string;
  spaceId: string;
  subscriptionId: string;
  runtimePartitionId: string;
  defaultProjectId: string;
}

export interface SaasLoginResponse {
  userId: string;
  csrfToken: string;
  expiresAt: string;
}

export type OnboardingCustomerState =
  "provisioning" | "ready_for_first_run" | "complete" | "recovering" | "support_required";

export type OnboardingCustomerStage =
  | "billing"
  | "runtime"
  | "project"
  | "activation"
  | "first_run"
  | "complete"
  | "compensation"
  | "support";

export interface OnboardingStatus {
  state: OnboardingCustomerState;
  stage: OnboardingCustomerStage;
  version: number;
  updatedAt: string;
  canStartFirstRun: boolean;
  tenantId?: string;
  spaceId?: string;
  defaultProjectId?: string;
  trialEndsAt?: string;
  supportReference?: string;
}

export class OnboardingApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryAfterSeconds: number | null;

  constructor(
    code: string,
    message: string,
    status: number,
    retryAfterSeconds: number | null = null,
  ) {
    super(message);
    this.name = "OnboardingApiError";
    this.code = code;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export async function fetchOnboardingCatalog(): Promise<OnboardingCatalog> {
  const payload = await requestJson("/saas/onboarding/catalog", { cache: "no-cache" });
  return parseCatalog(payload);
}

export async function requestOnboardingRegistration(
  body: OnboardingRegistrationRequest,
  idempotencyKey: string,
): Promise<OnboardingRegistrationResponse> {
  const payload = await requestJson("/saas/onboarding/registrations", {
    method: "POST",
    headers: mutationHeaders(idempotencyKey),
    body: JSON.stringify({
      email: body.email,
      display_name: body.displayName ?? null,
      tenant_name: body.tenantName,
      tenant_slug: body.tenantSlug,
      default_space_name: body.defaultSpaceName,
      default_space_slug: body.defaultSpaceSlug,
      plan_key: body.planKey,
      home_region: body.homeRegion,
    }),
  });
  return parseRegistration(payload);
}

export async function resendOnboardingVerification(
  registrationId: string,
  email: string,
  idempotencyKey: string,
): Promise<OnboardingRegistrationResponse> {
  requireUuidInput(registrationId, "registration ID");
  const payload = await requestJson(
    `/saas/onboarding/registrations/${encodeURIComponent(registrationId)}/resend`,
    {
      method: "POST",
      headers: mutationHeaders(idempotencyKey),
      body: JSON.stringify({ email }),
    },
  );
  return parseRegistration(payload);
}

export async function verifyOnboardingRegistration(
  registrationId: string,
  verificationToken: string,
  password: string,
  idempotencyKey: string,
): Promise<OnboardingVerificationResponse> {
  requireUuidInput(registrationId, "registration ID");
  const payload = await requestJson(
    `/saas/onboarding/registrations/${encodeURIComponent(registrationId)}/verify`,
    {
      method: "POST",
      headers: mutationHeaders(idempotencyKey),
      body: JSON.stringify({ verification_token: verificationToken, password }),
    },
  );
  return parseVerification(payload);
}

export async function loginSaas(email: string, password: string): Promise<SaasLoginResponse> {
  const payload = await requestJson("/saas/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const result = parseLogin(payload);
  storeSaasCsrf(result.csrfToken);
  return result;
}

export async function fetchOnboardingStatus(): Promise<OnboardingStatus> {
  const payload = await requestJson("/saas/onboarding/status", {
    cache: "no-store",
  });
  return parseStatus(payload);
}

function mutationHeaders(idempotencyKey: string): Headers {
  const normalized = idempotencyKey.trim();
  if (normalized === "" || normalized.length > IDEMPOTENCY_KEY_MAX_LENGTH) {
    throw new TypeError("idempotency key must contain between 1 and 128 characters");
  }
  return new Headers({
    "content-type": "application/json",
    "Idempotency-Key": normalized,
  });
}

async function requestJson(input: string, init?: RequestInit): Promise<unknown> {
  let response: Response;
  try {
    response = await hostFetch(input, init);
  } catch {
    throw new OnboardingApiError(
      "network_unavailable",
      "Could not reach the server. Check your connection and try again.",
      0,
    );
  }
  if (!response.ok) {
    if (response.status === 401) clearSaasCsrf();
    throw await parseErrorResponse(response);
  }
  try {
    return await response.json();
  } catch {
    throw new OnboardingApiError(
      "invalid_response",
      "The server returned an invalid response.",
      response.status,
    );
  }
}

async function parseErrorResponse(response: Response): Promise<OnboardingApiError> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  const retryAfterSeconds = parseRetryAfter(response.headers.get("Retry-After"));
  const structured = structuredError(payload);
  if (structured !== null) {
    return new OnboardingApiError(
      structured.code,
      structured.message,
      response.status,
      retryAfterSeconds,
    );
  }
  if (response.status === 422) {
    return new OnboardingApiError(
      "request_invalid",
      "Check the submitted values and try again.",
      response.status,
      retryAfterSeconds,
    );
  }
  return new OnboardingApiError(
    response.status >= 500 ? "service_unavailable" : "request_failed",
    response.status >= 500
      ? "The service is temporarily unavailable. Try again shortly."
      : "The request could not be completed.",
    response.status,
    retryAfterSeconds,
  );
}

function structuredError(payload: unknown): { code: string; message: string } | null {
  if (!isRecord(payload)) return null;
  for (const key of ["error", "detail"] as const) {
    const value = payload[key];
    if (
      isRecord(value) &&
      typeof value.code === "string" &&
      value.code.trim() !== "" &&
      typeof value.message === "string" &&
      value.message.trim() !== ""
    ) {
      return { code: value.code, message: value.message };
    }
  }
  return null;
}

function parseRetryAfter(value: string | null): number | null {
  if (value === null || !/^\d+$/.test(value)) return null;
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 86_400 ? seconds : null;
}

function parseCatalog(payload: unknown): OnboardingCatalog {
  const value = requireRecord(payload);
  if (
    value.schema_version !== 1 ||
    typeof value.revision !== "string" ||
    !SHA256_PATTERN.test(value.revision) ||
    !Array.isArray(value.plans) ||
    value.plans.length === 0 ||
    !Array.isArray(value.regions) ||
    value.regions.length === 0 ||
    !isPositiveInteger(value.verification_ttl_seconds)
  ) {
    return invalidResponse();
  }
  const plans = value.plans.map((raw): OnboardingCatalogPlan => {
    const plan = requireRecord(raw);
    if (
      !isNonEmptyString(plan.key) ||
      typeof plan.currency !== "string" ||
      !/^[A-Z]{3}$/.test(plan.currency) ||
      !isPositiveInteger(plan.trial_days) ||
      !isPositiveInteger(plan.trial_run_limit) ||
      !isPositiveInteger(plan.trial_concurrency_limit)
    ) {
      return invalidResponse();
    }
    return {
      key: plan.key,
      currency: plan.currency,
      trialDays: plan.trial_days,
      trialRunLimit: plan.trial_run_limit,
      trialConcurrencyLimit: plan.trial_concurrency_limit,
    };
  });
  const regions = value.regions.map((region) => {
    if (!isNonEmptyString(region)) return invalidResponse();
    return region;
  });
  return {
    schemaVersion: 1,
    revision: value.revision,
    plans,
    regions,
    verificationTtlSeconds: value.verification_ttl_seconds,
  };
}

function parseRegistration(payload: unknown): OnboardingRegistrationResponse {
  const value = requireRecord(payload);
  if (value.status !== "verification_pending") return invalidResponse();
  return {
    registrationId: requireUuid(value.registration_id),
    status: "verification_pending",
  };
}

function parseVerification(payload: unknown): OnboardingVerificationResponse {
  const value = requireRecord(payload);
  if (value.status !== "tenant_provisioning") return invalidResponse();
  return {
    registrationId: requireUuid(value.registration_id),
    status: "tenant_provisioning",
    onboardingId: requireUuid(value.onboarding_id),
    userId: requireUuid(value.user_id),
    tenantId: requireUuid(value.tenant_id),
    spaceId: requireUuid(value.space_id),
    subscriptionId: requireUuid(value.subscription_id),
    runtimePartitionId: requireUuid(value.runtime_partition_id),
    defaultProjectId: requireUuid(value.default_project_id),
  };
}

function parseLogin(payload: unknown): SaasLoginResponse {
  const value = requireRecord(payload);
  if (!isNonEmptyString(value.csrf_token) || !isIsoTimestamp(value.expires_at)) {
    return invalidResponse();
  }
  return {
    userId: requireUuid(value.user_id),
    csrfToken: value.csrf_token,
    expiresAt: value.expires_at,
  };
}

const CUSTOMER_STATES = new Set<OnboardingCustomerState>([
  "provisioning",
  "ready_for_first_run",
  "complete",
  "recovering",
  "support_required",
]);
const CUSTOMER_STAGES = new Set<OnboardingCustomerStage>([
  "billing",
  "runtime",
  "project",
  "activation",
  "first_run",
  "complete",
  "compensation",
  "support",
]);

function parseStatus(payload: unknown): OnboardingStatus {
  const value = requireRecord(payload);
  if (
    typeof value.state !== "string" ||
    !CUSTOMER_STATES.has(value.state as OnboardingCustomerState) ||
    typeof value.stage !== "string" ||
    !CUSTOMER_STAGES.has(value.stage as OnboardingCustomerStage) ||
    !isPositiveInteger(value.version) ||
    !isIsoTimestamp(value.updated_at) ||
    typeof value.can_start_first_run !== "boolean"
  ) {
    return invalidResponse();
  }
  const result: OnboardingStatus = {
    state: value.state as OnboardingCustomerState,
    stage: value.stage as OnboardingCustomerStage,
    version: value.version,
    updatedAt: value.updated_at,
    canStartFirstRun: value.can_start_first_run,
  };
  assignOptionalUuid(result, "tenantId", value.tenant_id);
  assignOptionalUuid(result, "spaceId", value.space_id);
  assignOptionalUuid(result, "defaultProjectId", value.default_project_id);
  if (value.trial_ends_at !== undefined) {
    if (!isIsoTimestamp(value.trial_ends_at)) return invalidResponse();
    result.trialEndsAt = value.trial_ends_at;
  }
  if (value.support_reference !== undefined) {
    if (!isNonEmptyString(value.support_reference)) return invalidResponse();
    result.supportReference = value.support_reference;
  }
  return result;
}

function assignOptionalUuid(
  target: OnboardingStatus,
  key: "tenantId" | "spaceId" | "defaultProjectId",
  value: unknown,
): void {
  if (value !== undefined) target[key] = requireUuid(value);
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) return invalidResponse();
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isIsoTimestamp(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "" && !Number.isNaN(Date.parse(value));
}

function requireUuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    return invalidResponse();
  }
  return value;
}

function requireUuidInput(value: string, field: string): void {
  if (!UUID_PATTERN.test(value)) throw new TypeError(`${field} must be a UUID`);
}

function invalidResponse(): never {
  throw new OnboardingApiError("invalid_response", "The server returned an invalid response.", 200);
}
