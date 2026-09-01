/**
 * Browser-only session material returned by the SaaS cookie login endpoint.
 *
 * The opaque authentication token remains in the server-issued HttpOnly cookie.
 * The only value JavaScript persists is the CSRF token needed for unsafe
 * same-origin requests. Keep it tab-scoped: a copied URL or another browser tab
 * must not inherit mutation authority implicitly.
 */

export const SAAS_CSRF_STORAGE_KEY = "omnigent.saas.csrf";

export function storeSaasCsrf(token: string): void {
  const normalized = token.trim();
  if (normalized === "") {
    clearSaasCsrf();
    return;
  }
  try {
    window.sessionStorage.setItem(SAAS_CSRF_STORAGE_KEY, normalized);
  } catch {
    // Sandboxed/locked-down browsers can deny storage. The caller may still
    // render and perform safe reads; unsafe requests will fail closed server-side.
  }
}

export function readSaasCsrf(): string | null {
  try {
    const value = window.sessionStorage.getItem(SAAS_CSRF_STORAGE_KEY)?.trim() ?? "";
    return value === "" ? null : value;
  } catch {
    return null;
  }
}

export function clearSaasCsrf(): void {
  try {
    window.sessionStorage.removeItem(SAAS_CSRF_STORAGE_KEY);
  } catch {
    // Clearing is best-effort when storage itself is unavailable. The server's
    // HttpOnly session remains the authentication authority.
  }
}
