import { clearCsrfToken, readCsrfToken, safeReturnTarget } from "@/lib/auth";
import type { Locale, MessageKey } from "@/lib/i18n";

export interface IdentityProvider {
  name: string;
  start_path: string;
  link_path: string;
  signup_path: string | null;
  authorization_origin: string;
}
export interface IdentityOptions {
  mode: "legacy" | "dual" | "casdoor";
  password_enabled: boolean;
  providers: IdentityProvider[];
}
export interface IdentityConnection {
  id: string;
  provider: string;
  email_normalized: string | null;
  email_verified: boolean;
  status: string;
}
export interface IdentityConflict {
  id: string;
  provider: string;
  email: string;
  display_name: string | null;
  review_status: string;
}
export class IdentityError extends Error {
  constructor(
    public code: string,
    public status: number = 0,
  ) {
    super(code);
  }
}

export async function identityJson<T>(
  url: string,
  init: RequestInit = {},
): Promise<T> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  init.signal?.addEventListener("abort", abort, { once: true });
  if (init.signal?.aborted) controller.abort();
  const timeout = window.setTimeout(abort, 30_000);
  try {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (["POST", "DELETE"].includes(init.method || "GET")) {
      headers.set("X-CSRF-Token", readCsrfToken());
    }
    const response = await fetch(url, {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
      headers,
      signal: controller.signal,
    });
    const payload =
      response.status === 204 ? {} : await response.json().catch(() => null);
    if (!response.ok) {
      if (response.status === 401) clearCsrfToken();
      throw new IdentityError(
        payload?.error?.code || payload?.detail?.code || "request_failed",
        response.status,
      );
    }
    if (payload === null || typeof payload !== "object")
      throw new IdentityError("invalid_response");
    return payload as T;
  } catch (cause) {
    if (cause instanceof IdentityError) throw cause;
    throw new IdentityError(
      controller.signal.aborted ? "request_timeout" : "network_unavailable",
    );
  } finally {
    window.clearTimeout(timeout);
    init.signal?.removeEventListener("abort", abort);
  }
}

const legacy: IdentityOptions = {
  mode: "legacy",
  password_enabled: true,
  providers: [],
};

function localPath(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.startsWith("/saas/auth/oidc/") &&
    !/[\\\r\n#]/.test(value)
  );
}

export async function identityOptions(
  signal?: AbortSignal,
): Promise<IdentityOptions> {
  try {
    const value = await identityJson<IdentityOptions>("/saas/auth/options", {
      signal,
    });
    if (
      !["legacy", "dual", "casdoor"].includes(value.mode) ||
      value.password_enabled !== (value.mode !== "casdoor") ||
      !Array.isArray(value.providers) ||
      value.providers.some(
        (provider) =>
          typeof provider.name !== "string" ||
          !localPath(provider.start_path) ||
          !localPath(provider.link_path) ||
          (provider.signup_path !== null && !localPath(provider.signup_path)) ||
          typeof provider.authorization_origin !== "string",
      )
    )
      throw new IdentityError("invalid_response");
    return value;
  } catch (cause) {
    if (cause instanceof IdentityError && cause.status === 404) return legacy;
    throw cause;
  }
}

export function providerStart(
  provider: IdentityProvider,
  target: string,
  locale: Locale,
  kind: "login" | "signup" = "login",
  reauthenticate = false,
): string {
  const endpoint =
    kind === "signup" ? provider.signup_path : provider.start_path;
  if (!endpoint || !localPath(endpoint))
    throw new IdentityError("invalid_response");
  const url = new URL(endpoint, window.location.origin);
  url.searchParams.set(
    "return_to",
    safeReturnTarget(target, window.location.origin),
  );
  url.searchParams.set("ui_locale", locale);
  if (reauthenticate) url.searchParams.set("reauthenticate", "true");
  return url.pathname + url.search;
}

export function reauthenticatePath(locale: Locale): string {
  return (
    "/saas/login?" +
    new URLSearchParams({
      return_to: "/saas/account/identities",
      reauthenticate: "1",
      ui_locale: locale,
    })
  );
}

export async function linkIdentity(
  provider: IdentityProvider,
  locale: Locale,
): Promise<string> {
  const url = new URL(provider.link_path, window.location.origin);
  url.searchParams.set("return_to", "/saas/account/identities");
  url.searchParams.set("ui_locale", locale);
  const result = await identityJson<{ authorization_url: string }>(
    url.pathname + url.search,
    { method: "POST" },
  );
  let target: URL;
  try {
    target = new URL(result.authorization_url);
  } catch {
    throw new IdentityError("invalid_response");
  }
  if (
    !["https:", "http:"].includes(target.protocol) ||
    target.origin !== provider.authorization_origin ||
    target.username ||
    target.password ||
    target.hash
  )
    throw new IdentityError("invalid_response");
  return target.href;
}

export async function logoutIdentity(
  options: IdentityOptions,
): Promise<string> {
  const result = await identityJson<{ logout_url?: string }>(
    "/saas/auth/logout",
    { method: "POST" },
  );
  clearCsrfToken();
  if (result.logout_url) {
    try {
      const url = new URL(result.logout_url);
      if (
        ["https:", "http:"].includes(url.protocol) &&
        !url.username &&
        !url.password &&
        !url.hash &&
        options.providers.some(
          (provider) => provider.authorization_origin === url.origin,
        )
      )
        return url.href;
    } catch {}
  }
  return "/saas/login";
}

export function identityErrorKey(cause: unknown): MessageKey {
  const code = cause instanceof IdentityError ? cause.code : "request_failed";
  if (
    [
      "recent_authentication_required",
      "authorization_snapshot_stale",
      "csrf_invalid",
    ].includes(code)
  )
    return "identity.reauthenticate";
  if (code === "identity_conflict_rejected") return "identity.rejected";
  if (code === "identity_conflict_manual_review_required")
    return "identity.manualReview";
  if (code === "reauthentication_identity_mismatch")
    return "identity.wrongAccount";
  if (code === "network_unavailable") return "error.network";
  if (code === "request_timeout") return "error.timeout";
  if (code === "invalid_response") return "error.invalidResponse";
  return "error.unavailable";
}
