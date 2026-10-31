export const CSRF_KEY = "omnigent.saas.csrf";

export function clearCsrfToken() {
  for (const name of ["sessionStorage", "localStorage"] as const) {
    try {
      window[name].removeItem(CSRF_KEY);
    } catch {
      // A restricted storage backend must not hide the actual login error.
    }
  }
}

export function readCsrfToken(): string {
  for (const name of ["localStorage", "sessionStorage"] as const) {
    try {
      const value = window[name].getItem(CSRF_KEY);
      if (value !== null) return value;
    } catch {}
  }
  return "";
}

export function persistCsrfToken(token: string) {
  let persisted = false;
  for (const name of ["sessionStorage", "localStorage"] as const) {
    try {
      window[name].setItem(CSRF_KEY, token);
      persisted = true;
    } catch {
      // The other browser storage may still be available.
    }
  }
  if (!persisted) {
    throw new Error(
      "Browser storage is unavailable. Enable site storage and try again.",
    );
  }
}

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
    if (response.status === 401) clearCsrfToken();
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
  // The HttpOnly session cookie is shared across same-origin tabs, so the
  // matching double-submit token must be shared too. Keep sessionStorage for
  // compatibility with existing admin surfaces and localStorage for new tabs.
  persistCsrfToken(payload.csrf_token);
  const bootstrap = await fetch("/saas/auth/bootstrap", {
    credentials: "same-origin",
    cache: "no-store",
    signal,
  });
  if (bootstrap.status === 404) return null;
  if (!bootstrap.ok)
    throw new Error("Could not load your workspace. Try again.");
  const account = await bootstrap.json();
  return account.next === "/setup" ? "/setup" : null;
}
