export const CSRF_KEY = "omnigent.saas.csrf";

export function safeReturnTarget(value: string | null, origin: string): string {
  try {
    const target = new URL(value || "/", origin);
    return target.origin === origin && target.pathname.startsWith("/")
      ? target.pathname + target.search + target.hash
      : "/";
  } catch {
    return "/";
  }
}

export async function signIn(
  email: string,
  password: string,
  signal: AbortSignal,
) {
  let response: Response;
  try {
    response = await fetch("/saas/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
      signal,
    });
  } catch {
    throw new Error(
      signal.aborted
        ? "The request timed out. Please try again."
        : "Could not reach the server. Check your connection and try again.",
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
          : "Check your email and password and try again.";
    const retry = response.headers.get("Retry-After");
    throw new Error(
      retry ? `${message} Try again in ${retry} seconds.` : message,
    );
  }
  if (typeof payload?.csrf_token !== "string" || !payload.csrf_token.trim()) {
    throw new Error(
      "The server returned an invalid response. Please try again.",
    );
  }
  sessionStorage.setItem(CSRF_KEY, payload.csrf_token);
}
