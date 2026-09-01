import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  OnboardingApiError,
  fetchOnboardingCatalog,
  fetchOnboardingStatus,
  loginSaas,
  requestOnboardingRegistration,
  resendOnboardingVerification,
  verifyOnboardingRegistration,
} from "./saasOnboardingApi";
import { SAAS_CSRF_STORAGE_KEY } from "./saasSession";

const ID = "00000000-0000-4000-8000-000000000001";
const ID_2 = "00000000-0000-4000-8000-000000000002";
const ID_3 = "00000000-0000-4000-8000-000000000003";
const ID_4 = "00000000-0000-4000-8000-000000000004";
const ID_5 = "00000000-0000-4000-8000-000000000005";
const ID_6 = "00000000-0000-4000-8000-000000000006";
const ID_7 = "00000000-0000-4000-8000-000000000007";
const ID_8 = "00000000-0000-4000-8000-000000000008";

function response(body: unknown, status = 200, headers?: Record<string, string>): Response {
  return new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  window.sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("onboarding catalog", () => {
  it("strictly maps the public catalog projection", async () => {
    fetchMock.mockResolvedValueOnce(
      response({
        schema_version: 1,
        revision: "a".repeat(64),
        plans: [
          {
            key: "starter",
            currency: "USD",
            trial_days: 14,
            trial_run_limit: 100,
            trial_concurrency_limit: 2,
          },
        ],
        regions: ["cn-east-1"],
        verification_ttl_seconds: 1800,
      }),
    );

    await expect(fetchOnboardingCatalog()).resolves.toEqual({
      schemaVersion: 1,
      revision: "a".repeat(64),
      plans: [
        {
          key: "starter",
          currency: "USD",
          trialDays: 14,
          trialRunLimit: 100,
          trialConcurrencyLimit: 2,
        },
      ],
      regions: ["cn-east-1"],
      verificationTtlSeconds: 1800,
    });
    expect(fetchMock).toHaveBeenCalledWith("/saas/onboarding/catalog", { cache: "no-cache" });
  });

  it("rejects a malformed success payload instead of trusting it", async () => {
    fetchMock.mockResolvedValueOnce(response({ schema_version: 1, plans: [] }));
    await expect(fetchOnboardingCatalog()).rejects.toMatchObject({
      code: "invalid_response",
      status: 200,
    });
  });

  it("treats malformed response identifiers as a server contract error", async () => {
    fetchMock.mockResolvedValueOnce(
      response({ registration_id: "not-a-uuid", status: "verification_pending" }, 202),
    );
    const promise = requestOnboardingRegistration(
      {
        email: "owner@example.com",
        tenantName: "Acme",
        tenantSlug: "acme",
        defaultSpaceName: "General",
        defaultSpaceSlug: "general",
        planKey: "starter",
        homeRegion: "cn-east-1",
      },
      "malformed-response",
    );
    const error = await promise.catch((value: unknown) => value);
    expect(error).toBeInstanceOf(OnboardingApiError);
    expect(error).toMatchObject({ code: "invalid_response" });
  });
});

describe("registration mutations", () => {
  it("sends the exact registration wire shape and idempotency key", async () => {
    fetchMock.mockResolvedValueOnce(
      response({ registration_id: ID, status: "verification_pending" }, 202),
    );
    const result = await requestOnboardingRegistration(
      {
        email: "owner@example.com",
        displayName: "Owner",
        tenantName: "Acme",
        tenantSlug: "acme",
        defaultSpaceName: "General",
        defaultSpaceSlug: "general",
        planKey: "starter",
        homeRegion: "cn-east-1",
      },
      "register-1",
    );

    expect(result).toEqual({ registrationId: ID, status: "verification_pending" });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/saas/onboarding/registrations");
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("Idempotency-Key")).toBe("register-1");
    expect(JSON.parse(init.body as string)).toEqual({
      email: "owner@example.com",
      display_name: "Owner",
      tenant_name: "Acme",
      tenant_slug: "acme",
      default_space_name: "General",
      default_space_slug: "general",
      plan_key: "starter",
      home_region: "cn-east-1",
    });
  });

  it("resends and verifies through UUID-scoped endpoints", async () => {
    fetchMock
      .mockResolvedValueOnce(response({ registration_id: ID, status: "verification_pending" }, 202))
      .mockResolvedValueOnce(
        response(
          {
            registration_id: ID,
            status: "tenant_provisioning",
            onboarding_id: ID_2,
            user_id: ID_3,
            tenant_id: ID_4,
            space_id: ID_5,
            subscription_id: ID_6,
            runtime_partition_id: ID_7,
            default_project_id: ID_8,
          },
          202,
        ),
      );

    await resendOnboardingVerification(ID, "owner@example.com", "resend-1");
    const resend = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(resend[0]).toBe(`/saas/onboarding/registrations/${ID}/resend`);
    expect(JSON.parse(resend[1].body as string)).toEqual({ email: "owner@example.com" });

    const verified = await verifyOnboardingRegistration(ID, "opaque", "long-enough-12", "verify-1");
    expect(verified.defaultProjectId).toBe(ID_8);
    const verify = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(verify[0]).toBe(`/saas/onboarding/registrations/${ID}/verify`);
    expect(new Headers(verify[1].headers).get("Idempotency-Key")).toBe("verify-1");
    expect(JSON.parse(verify[1].body as string)).toEqual({
      verification_token: "opaque",
      password: "long-enough-12",
    });
  });

  it("rejects invalid client identifiers and idempotency keys before fetching", async () => {
    await expect(
      resendOnboardingVerification("not-a-uuid", "owner@example.com", "resend-1"),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      requestOnboardingRegistration(
        {
          email: "owner@example.com",
          tenantName: "Acme",
          tenantSlug: "acme",
          defaultSpaceName: "General",
          defaultSpaceSlug: "general",
          planKey: "starter",
          homeRegion: "cn-east-1",
        },
        " ",
      ),
    ).rejects.toBeInstanceOf(TypeError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("SaaS login and onboarding status", () => {
  it("stores the login CSRF token in sessionStorage", async () => {
    fetchMock.mockResolvedValueOnce(
      response({ user_id: ID, csrf_token: "csrf-value", expires_at: "2026-09-02T01:00:00Z" }),
    );

    await expect(loginSaas("owner@example.com", "long-enough-12")).resolves.toEqual({
      userId: ID,
      csrfToken: "csrf-value",
      expiresAt: "2026-09-02T01:00:00Z",
    });
    expect(window.sessionStorage.getItem(SAAS_CSRF_STORAGE_KEY)).toBe("csrf-value");
  });

  it("parses the allowlisted customer status projection", async () => {
    fetchMock.mockResolvedValueOnce(
      response({
        state: "ready_for_first_run",
        stage: "first_run",
        version: 5,
        updated_at: "2026-09-02T01:00:00Z",
        can_start_first_run: true,
        tenant_id: ID,
        space_id: ID_2,
        default_project_id: ID_3,
        trial_ends_at: "2026-09-16T01:00:00Z",
      }),
    );

    const status = await fetchOnboardingStatus();
    expect(status).toMatchObject({
      state: "ready_for_first_run",
      stage: "first_run",
      canStartFirstRun: true,
      tenantId: ID,
      defaultProjectId: ID_3,
    });
  });
});

describe("strict error handling", () => {
  it("keeps structured error code, status, and bounded Retry-After", async () => {
    fetchMock.mockResolvedValueOnce(
      response(
        {
          detail: {
            code: "registration_rate_limited",
            message: "registration request rate limit exceeded",
          },
        },
        429,
        { "Retry-After": "37" },
      ),
    );

    const promise = requestOnboardingRegistration(
      {
        email: "owner@example.com",
        tenantName: "Acme",
        tenantSlug: "acme",
        defaultSpaceName: "General",
        defaultSpaceSlug: "general",
        planKey: "starter",
        homeRegion: "cn-east-1",
      },
      "register-rate-limit",
    );
    await expect(promise).rejects.toMatchObject({
      code: "registration_rate_limited",
      status: 429,
      retryAfterSeconds: 37,
    });
  });

  it("does not surface malformed server error bodies", async () => {
    fetchMock.mockResolvedValueOnce(response({ detail: { message: 17 } }, 503));
    const error = await fetchOnboardingCatalog().catch((value: unknown) => value);
    expect(error).toBeInstanceOf(OnboardingApiError);
    expect(error).toMatchObject({
      code: "service_unavailable",
      message: "The service is temporarily unavailable. Try again shortly.",
    });
  });

  it("maps network failures to one stable client error", async () => {
    fetchMock.mockRejectedValueOnce(new Error("secret transport detail"));
    await expect(fetchOnboardingCatalog()).rejects.toMatchObject({
      code: "network_unavailable",
      status: 0,
    });
  });

  it("clears a stale CSRF token on 401", async () => {
    window.sessionStorage.setItem(SAAS_CSRF_STORAGE_KEY, "stale");
    fetchMock.mockResolvedValueOnce(
      response({ error: { code: "invalid_session", message: "login required" } }, 401),
    );
    await expect(fetchOnboardingStatus()).rejects.toMatchObject({ code: "invalid_session" });
    expect(window.sessionStorage.getItem(SAAS_CSRF_STORAGE_KEY)).toBeNull();
  });
});
