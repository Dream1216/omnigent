const SAFE_DEFAULT_RETURN_TO = "/";

/** Keep post-auth navigation on the current origin. */
export function sanitizeAuthReturnTo(raw: string | null): string {
  if (raw === null || raw === "") return SAFE_DEFAULT_RETURN_TO;
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) {
    return SAFE_DEFAULT_RETURN_TO;
  }
  try {
    const resolved = new URL(raw, window.location.origin);
    if (resolved.origin !== window.location.origin) return SAFE_DEFAULT_RETURN_TO;
    return resolved.pathname + resolved.search + resolved.hash;
  } catch {
    return SAFE_DEFAULT_RETURN_TO;
  }
}
