import { render, screen } from "@testing-library/react";
import { Outlet, MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { FALLBACK_SERVER_INFO } from "@/lib/capabilities";
import { CapabilitiesProvider } from "@/lib/CapabilitiesContext";

vi.mock("@/lib/analytics", () => ({ useOmnigentPageView: vi.fn() }));
vi.mock("@/shell/AppShell", () => ({
  AppShell: () => (
    <div>
      <span>app shell</span>
      <Outlet />
    </div>
  ),
}));
vi.mock("@/pages/ChatPage", () => ({ ChatPage: () => <div>chat page</div> }));
vi.mock("@/pages/NotFoundPage", () => ({ NotFoundPage: () => <div>not found</div> }));
vi.mock("@/pages/LoginPage", () => ({ LoginPage: () => <div>accounts login page</div> }));
vi.mock("@/pages/RegisterPage", () => ({
  RegisterPage: () => <div>invite registration page</div>,
}));
vi.mock("@/pages/SaasLoginPage", () => ({
  SaasLoginPage: () => <div>saas login page</div>,
}));
vi.mock("@/pages/SaasSignupPage", () => ({
  SaasSignupPage: () => <div>saas signup page</div>,
}));
vi.mock("@/pages/SaasVerificationPage", () => ({
  SaasVerificationPage: () => <div>saas verification page</div>,
}));
vi.mock("@/pages/SaasOnboardingStatusPage", () => ({
  SaasOnboardingStatusPage: () => <div>saas onboarding status page</div>,
}));
vi.mock("@/pages/UsagePage", () => ({ UsagePage: () => <div>usage page</div> }));
vi.mock("@/pages/SettingsPage", async () => {
  const { useLocation } = await import("react-router-dom");
  return {
    SettingsPage: () => <div data-testid="settings-location">{useLocation().pathname}</div>,
  };
});

import App from "./App";

function renderUsageRoute(enabled: boolean) {
  const info: typeof FALLBACK_SERVER_INFO = {
    ...FALLBACK_SERVER_INFO,
    features: enabled ? { usage_page: true } : {},
  };
  return render(
    <CapabilitiesProvider info={info}>
      <MemoryRouter initialEntries={["/usage"]}>
        <App />
      </MemoryRouter>
    </CapabilitiesProvider>,
  );
}

function renderRoute(
  path: string,
  info: typeof FALLBACK_SERVER_INFO = FALLBACK_SERVER_INFO,
  basename?: string,
) {
  return render(
    <CapabilitiesProvider info={info}>
      <MemoryRouter initialEntries={[path]}>
        <App basename={basename} />
      </MemoryRouter>
    </CapabilitiesProvider>,
  );
}

const SAAS_SERVER_INFO: typeof FALLBACK_SERVER_INFO = {
  ...FALLBACK_SERVER_INFO,
  login_url: "/saas/login",
};

const ACCOUNTS_SERVER_INFO: typeof FALLBACK_SERVER_INFO = {
  ...FALLBACK_SERVER_INFO,
  accounts_enabled: true,
  login_url: "/login",
};

describe("Usage release feature route", () => {
  it("does not register /usage while the feature is off", async () => {
    renderUsageRoute(false);
    expect(await screen.findByText("not found")).toBeInTheDocument();
    expect(screen.queryByText("usage page")).toBeNull();
  });

  it("registers /usage while the feature is on", async () => {
    renderUsageRoute(true);
    expect(await screen.findByText("usage page")).toBeInTheDocument();
    expect(screen.queryByText("not found")).toBeNull();
  });
});

describe("Settings routes", () => {
  it("redirects bare settings to the canonical General section", async () => {
    renderRoute("/settings");

    expect(await screen.findByTestId("settings-location")).toHaveTextContent("/settings/general");
  });

  it("preserves an explicit settings section", async () => {
    renderRoute("/settings/appearance");

    expect(await screen.findByTestId("settings-location")).toHaveTextContent(
      "/settings/appearance",
    );
  });
});

describe("SaaS authentication and onboarding routes", () => {
  it.each([
    ["/saas/login", "saas login page"],
    ["/signup", "saas signup page"],
    ["/signup/verify?registration_id=reg-1", "saas verification page"],
    ["/signup/status", "saas onboarding status page"],
  ])("registers %s only for the SaaS provider", async (path, pageText) => {
    renderRoute(path, SAAS_SERVER_INFO);

    expect(await screen.findByText(pageText)).toBeInTheDocument();
    expect(screen.queryByText("app shell")).toBeNull();
  });

  it.each(["/saas/login", "/signup", "/signup/verify?registration_id=reg-1", "/signup/status"])(
    "does not register %s for a non-SaaS deployment",
    async (path) => {
      renderRoute(path);

      expect(await screen.findByText("not found")).toBeInTheDocument();
      expect(screen.queryByText(/saas .* page/)).toBeNull();
    },
  );

  it.each([
    ["/embed/saas/login", "saas login page"],
    ["/embed/signup", "saas signup page"],
    ["/embed/signup/verify?registration_id=reg-1", "saas verification page"],
    ["/embed/signup/status", "saas onboarding status page"],
  ])("registers the basenamed route %s", async (path, pageText) => {
    renderRoute(path, SAAS_SERVER_INFO, "/embed");

    expect(await screen.findByText(pageText)).toBeInTheDocument();
    expect(screen.queryByText("app shell")).toBeNull();
  });

  it("preserves the accounts login and invite-registration routes", async () => {
    const { unmount } = renderRoute("/login", ACCOUNTS_SERVER_INFO);
    expect(await screen.findByText("accounts login page")).toBeInTheDocument();
    unmount();

    renderRoute("/register?invite=invite-1", ACCOUNTS_SERVER_INFO);
    expect(await screen.findByText("invite registration page")).toBeInTheDocument();
  });
});
