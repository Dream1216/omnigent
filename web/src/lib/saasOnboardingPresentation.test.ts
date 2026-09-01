import { afterEach, describe, expect, it } from "vitest";
import {
  consumeVerificationToken,
  humanizeCatalogKey,
  onboardingStageIndex,
  slugifyOnboardingName,
} from "./saasOnboardingPresentation";

afterEach(() => window.history.replaceState(null, "", "/"));

describe("SaaS onboarding presentation boundaries", () => {
  it("creates server-compatible slugs", () => {
    expect(slugifyOnboardingName("  Acme Research & AI  ")).toBe("acme-research-ai");
    expect(slugifyOnboardingName("---North___Star---")).toBe("north-star");
  });

  it("consumes the verification fragment without leaving the credential in the URL", () => {
    window.history.replaceState(null, "", "/signup/verify?registration_id=one#token=secret-value");

    expect(consumeVerificationToken()).toBe("secret-value");
    expect(window.location.pathname + window.location.search).toBe(
      "/signup/verify?registration_id=one",
    );
    expect(window.location.hash).toBe("");
  });

  it("formats catalog keys and maps real stages without inventing a percentage", () => {
    expect(humanizeCatalogKey("cn-east-1")).toBe("Cn East 1");
    expect(onboardingStageIndex("billing")).toBe(0);
    expect(onboardingStageIndex("first_run")).toBe(4);
    expect(onboardingStageIndex("support")).toBe(-1);
  });
});
