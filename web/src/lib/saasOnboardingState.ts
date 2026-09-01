const PENDING_REGISTRATION_KEY = "omnigent.saas.onboarding.pending";

export interface PendingOnboardingRegistration {
  registrationId: string;
  email: string;
}

export function storePendingOnboardingRegistration(
  registration: PendingOnboardingRegistration,
): void {
  try {
    window.sessionStorage.setItem(PENDING_REGISTRATION_KEY, JSON.stringify(registration));
  } catch {
    // Private browsing or embedded storage policies can disable sessionStorage.
  }
}

export function readPendingOnboardingRegistration(): PendingOnboardingRegistration | null {
  try {
    const raw = window.sessionStorage.getItem(PENDING_REGISTRATION_KEY);
    if (raw === null) return null;
    const value = JSON.parse(raw) as Partial<PendingOnboardingRegistration>;
    if (typeof value.registrationId !== "string" || typeof value.email !== "string") return null;
    return { registrationId: value.registrationId, email: value.email };
  } catch {
    return null;
  }
}

export function clearPendingOnboardingRegistration(): void {
  try {
    window.sessionStorage.removeItem(PENDING_REGISTRATION_KEY);
  } catch {
    // Best effort; the record contains no credential or verification token.
  }
}
