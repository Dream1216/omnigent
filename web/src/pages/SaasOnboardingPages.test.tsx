import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as onboardingApi from "@/lib/saasOnboardingApi";
import { OnboardingApiError } from "@/lib/saasOnboardingApi";
import { SaasLoginPage } from "./SaasLoginPage";
import { SaasOnboardingStatusPage } from "./SaasOnboardingStatusPage";
import { SaasSignupPage } from "./SaasSignupPage";
import { SaasVerificationPage } from "./SaasVerificationPage";

vi.mock("@/lib/saasOnboardingApi", async (importOriginal) => {
  const actual = await importOriginal<typeof onboardingApi>();
  return {
    ...actual,
    fetchOnboardingCatalog: vi.fn(),
    requestOnboardingRegistration: vi.fn(),
    resendOnboardingVerification: vi.fn(),
    verifyOnboardingRegistration: vi.fn(),
    loginSaas: vi.fn(),
    fetchOnboardingStatus: vi.fn(),
  };
});

const REGISTRATION_ID = "11111111-1111-4111-8111-111111111111";
const CATALOG: onboardingApi.OnboardingCatalog = {
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
  regions: ["cn-east-1", "us-west-2"],
  verificationTtlSeconds: 3600,
};

function renderPage(page: React.ReactNode, path = "/") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "/");
  vi.mocked(onboardingApi.fetchOnboardingCatalog).mockResolvedValue(CATALOG);
  vi.mocked(onboardingApi.requestOnboardingRegistration).mockResolvedValue({
    registrationId: REGISTRATION_ID,
    status: "verification_pending",
  });
  vi.mocked(onboardingApi.resendOnboardingVerification).mockResolvedValue({
    registrationId: REGISTRATION_ID,
    status: "verification_pending",
  });
  vi.mocked(onboardingApi.loginSaas).mockResolvedValue({
    userId: "22222222-2222-4222-8222-222222222222",
    csrfToken: "csrf",
    expiresAt: "2026-09-02T08:00:00Z",
  });
  vi.mocked(onboardingApi.verifyOnboardingRegistration).mockResolvedValue({
    registrationId: REGISTRATION_ID,
    status: "tenant_provisioning",
    onboardingId: "33333333-3333-4333-8333-333333333333",
    userId: "22222222-2222-4222-8222-222222222222",
    tenantId: "44444444-4444-4444-8444-444444444444",
    spaceId: "55555555-5555-4555-8555-555555555555",
    subscriptionId: "66666666-6666-4666-8666-666666666666",
    runtimePartitionId: "77777777-7777-4777-8777-777777777777",
    defaultProjectId: "88888888-8888-4888-8888-888888888888",
  });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  window.history.replaceState(null, "", "/");
});

describe("SaaS login entry", () => {
  it("only reveals self-service signup after the live catalog succeeds", async () => {
    renderPage(<SaasLoginPage />, "/saas/login");
    expect(await screen.findByRole("link", { name: /create a workspace/i })).toHaveAttribute(
      "href",
      "/signup",
    );
  });

  it("keeps signup hidden when catalog capability is unavailable", async () => {
    vi.mocked(onboardingApi.fetchOnboardingCatalog).mockRejectedValue(new Error("offline"));
    renderPage(<SaasLoginPage />, "/saas/login");
    await waitFor(() => expect(onboardingApi.fetchOnboardingCatalog).toHaveBeenCalled());
    expect(screen.queryByRole("link", { name: /create a workspace/i })).toBeNull();
  });

  it("shows a bounded login error without exposing a raw response", async () => {
    vi.mocked(onboardingApi.loginSaas).mockRejectedValue(
      new OnboardingApiError("invalid_credentials", "database detail", 401),
    );
    renderPage(<SaasLoginPage />, "/saas/login");
    fireEvent.change(screen.getByLabelText(/work email/i), { target: { value: "a@b.example" } });
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: "password" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not complete/i);
    expect(screen.queryByText(/database detail/i)).toBeNull();
  });
});

describe("SaaS registration", () => {
  it("renders server-provided plan/region facts and submits the complete tenant boundary", async () => {
    renderPage(<SaasSignupPage />, "/signup");
    expect(await screen.findByText("14-day trial · 100 runs")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /cn east 1/i })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/work email/i), {
      target: { value: "OWNER@EXAMPLE.COM" },
    });
    fireEvent.change(screen.getByLabelText(/organization name/i), {
      target: { value: "Acme Research" },
    });
    expect(screen.getByLabelText(/organization url/i)).toHaveValue("acme-research");
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    await waitFor(() =>
      expect(onboardingApi.requestOnboardingRegistration).toHaveBeenCalledTimes(1),
    );
    expect(onboardingApi.requestOnboardingRegistration).toHaveBeenCalledWith(
      expect.objectContaining({
        email: "owner@example.com",
        tenantName: "Acme Research",
        tenantSlug: "acme-research",
        defaultSpaceName: "General",
        defaultSpaceSlug: "general",
        planKey: "starter",
        homeRegion: "cn-east-1",
      }),
      expect.stringMatching(/^signup-/),
    );
    expect(window.sessionStorage.getItem("omnigent.saas.onboarding.pending")).toContain(
      REGISTRATION_ID,
    );
  });

  it("fails closed when the catalog is unavailable", async () => {
    vi.mocked(onboardingApi.fetchOnboardingCatalog).mockRejectedValue(new Error("offline"));
    renderPage(<SaasSignupPage />, "/signup");
    expect(
      await screen.findByText(/registration is not available/i, undefined, { timeout: 3_000 }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /continue/i })).toBeNull();
  });
});

describe("SaaS email verification", () => {
  it("removes the fragment token, verifies, logs in, and clears pending state", async () => {
    window.sessionStorage.setItem(
      "omnigent.saas.onboarding.pending",
      JSON.stringify({ registrationId: REGISTRATION_ID, email: "owner@example.com" }),
    );
    window.history.replaceState(
      null,
      "",
      `/signup/verify?registration_id=${REGISTRATION_ID}#token=top-secret`,
    );
    renderPage(<SaasVerificationPage />, `/signup/verify?registration_id=${REGISTRATION_ID}`);
    await screen.findByText(/secure your account/i);
    expect(window.location.hash).toBe("");
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "a-strong-password" },
    });
    fireEvent.change(screen.getByLabelText(/confirm password/i), {
      target: { value: "a-strong-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: /verify and continue/i }));

    await waitFor(() =>
      expect(onboardingApi.verifyOnboardingRegistration).toHaveBeenCalledWith(
        REGISTRATION_ID,
        "top-secret",
        "a-strong-password",
        expect.stringMatching(/^verify-/),
      ),
    );
    expect(onboardingApi.loginSaas).toHaveBeenCalledWith("owner@example.com", "a-strong-password");
    expect(window.sessionStorage.getItem("omnigent.saas.onboarding.pending")).toBeNull();
  });

  it("offers a privacy-preserving resend path when no token is present", async () => {
    window.sessionStorage.setItem(
      "omnigent.saas.onboarding.pending",
      JSON.stringify({ registrationId: REGISTRATION_ID, email: "owner@example.com" }),
    );
    renderPage(<SaasVerificationPage />, `/signup/verify?registration_id=${REGISTRATION_ID}`);
    fireEvent.click(await screen.findByRole("button", { name: /send another email/i }));
    expect(await screen.findByText(/if this address can receive mail/i)).toBeInTheDocument();
  });
});

describe("SaaS provisioning status", () => {
  it("renders ready state as discrete completed stages", async () => {
    vi.mocked(onboardingApi.fetchOnboardingStatus).mockResolvedValue({
      state: "ready_for_first_run",
      stage: "first_run",
      version: 5,
      updatedAt: "2026-09-02T08:00:00Z",
      canStartFirstRun: true,
    });
    renderPage(<SaasOnboardingStatusPage />, "/signup/status");
    expect(await screen.findByText(/your organization is ready/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /open workspace/i })).toBeInTheDocument();
    expect(screen.queryByText(/%/)).toBeNull();
  });

  it("stops at a customer-safe support reference", async () => {
    vi.mocked(onboardingApi.fetchOnboardingStatus).mockResolvedValue({
      state: "support_required",
      stage: "support",
      version: 7,
      updatedAt: "2026-09-02T08:00:00Z",
      canStartFirstRun: false,
      supportReference: "ob-safe-reference",
    });
    renderPage(<SaasOnboardingStatusPage />, "/signup/status");
    expect(await screen.findByText("ob-safe-reference")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /open workspace/i })).toBeNull();
  });

  it("offers login when the cookie session has expired", async () => {
    vi.mocked(onboardingApi.fetchOnboardingStatus).mockRejectedValue(
      new OnboardingApiError("authentication_required", "hidden", 401),
    );
    renderPage(<SaasOnboardingStatusPage />, "/signup/status");
    expect(
      await screen.findByRole("link", { name: /sign in to continue/i }, { timeout: 3_000 }),
    ).toHaveAttribute("href", expect.stringContaining("/saas/login"));
  });
});
