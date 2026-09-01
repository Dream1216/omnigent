import { OnboardingApiError, type OnboardingCustomerStage } from "./saasOnboardingApi";

export const TENANT_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export const ONBOARDING_STAGES: readonly {
  key: Exclude<OnboardingCustomerStage, "compensation" | "support">;
  label: string;
  description: string;
}[] = [
  { key: "billing", label: "Trial access", description: "Preparing your trial entitlements" },
  { key: "runtime", label: "Runtime", description: "Allocating an isolated runtime" },
  { key: "project", label: "Project", description: "Creating your first project" },
  { key: "activation", label: "Activation", description: "Activating your workspace" },
  { key: "first_run", label: "Ready", description: "Your workspace is ready for its first run" },
] as const;

export function slugifyOnboardingName(value: string): string {
  return value
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
}

export function humanizeCatalogKey(value: string): string {
  return value
    .split(/[-_]/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function consumeVerificationToken(): string | null {
  const fragment = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  const token = new URLSearchParams(fragment).get("token")?.trim() ?? "";
  if (window.location.hash !== "") {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  }
  return token === "" ? null : token;
}

export function onboardingErrorMessage(error: unknown): string {
  if (!(error instanceof OnboardingApiError)) {
    return "Something went wrong. Try again.";
  }
  if (error.status === 429) {
    const wait = error.retryAfterSeconds;
    return wait === null
      ? "Too many attempts. Wait a moment and try again."
      : `Too many attempts. Try again in ${wait} seconds.`;
  }
  switch (error.code) {
    case "network_unavailable":
      return "We could not reach the service. Check your connection and try again.";
    case "plan_unavailable":
    case "region_unavailable":
      return "That plan or region is no longer available. Refresh the catalog and choose again.";
    case "identity_confirmation_required":
      return "This email already has an account. Sign in to continue.";
    case "verification_expired":
    case "verification_invalid":
    case "verification_token_invalid":
      return "This verification link is invalid or has expired. Request a new email.";
    case "service_unavailable":
      return "Registration is temporarily unavailable. Try again shortly.";
    default:
      return "We could not complete that request. Check your details and try again.";
  }
}

export function onboardingStageIndex(stage: OnboardingCustomerStage): number {
  if (stage === "complete") return ONBOARDING_STAGES.length;
  if (stage === "compensation" || stage === "support") return -1;
  return ONBOARDING_STAGES.findIndex((entry) => entry.key === stage);
}
