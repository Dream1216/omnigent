import { CSRF_KEY } from "@/lib/auth";

export const PENDING_REGISTRATION_KEY = "omnigent.saas.pending-registration";

export interface PendingRegistration {
  email: string;
  registrationId: string;
  verifyKey: string;
}

export interface CatalogPlan {
  key: string;
  trial_concurrency_limit: number;
  trial_days: number;
  trial_run_limit: number;
}

export interface OnboardingCatalog {
  plans: CatalogPlan[];
  regions: string[];
}

export interface OnboardingStatus {
  stage: string;
  state: string;
}

export function newIdempotencyKey(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

export function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 63);
}

export function readPendingRegistration(): PendingRegistration | null {
  try {
    const value = JSON.parse(
      sessionStorage.getItem(PENDING_REGISTRATION_KEY) || "null",
    );
    return value &&
      typeof value.registrationId === "string" &&
      typeof value.email === "string" &&
      typeof value.verifyKey === "string"
      ? value
      : null;
  } catch {
    return null;
  }
}

export function savePendingRegistration(value: PendingRegistration): void {
  sessionStorage.setItem(PENDING_REGISTRATION_KEY, JSON.stringify(value));
}

export function clearPendingRegistration(): void {
  sessionStorage.removeItem(PENDING_REGISTRATION_KEY);
}

export function mutation(body: unknown, idempotencyKey: string): RequestInit {
  return {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify(body),
  };
}

export async function requestJson<T>(
  url: string,
  options: RequestInit = {},
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      credentials: "same-origin",
      ...options,
    });
  } catch {
    throw new Error(
      "Could not reach the server. Check your connection and try again.",
    );
  }
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401) sessionStorage.removeItem(CSRF_KEY);
    const detail = payload?.detail || payload?.error;
    const message =
      typeof detail?.message === "string"
        ? detail.message
        : response.status >= 500
          ? "The service is temporarily unavailable. Try again shortly."
          : "Check the submitted values and try again.";
    const retry = response.headers.get("Retry-After");
    throw new Error(
      retry ? `${message} Try again in ${retry} seconds.` : message,
    );
  }
  if (!payload || typeof payload !== "object") {
    throw new Error("The server returned an invalid response.");
  }
  return payload as T;
}
