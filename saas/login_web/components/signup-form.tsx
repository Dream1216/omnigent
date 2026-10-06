"use client";

import { ArrowRight, LoaderCircle } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useI18n } from "@/lib/i18n";
import {
  mutation,
  newIdempotencyKey,
  requestJson,
  savePendingRegistration,
  slugify,
  type OnboardingCatalog,
} from "@/lib/onboarding";

interface RegistrationResponse {
  registration_id: string;
}

export function SignupForm() {
  const { locale, t } = useI18n();
  const [catalog, setCatalog] = useState<OnboardingCatalog | null>(null);
  const [catalogError, setCatalogError] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [tenantSlug, setTenantSlug] = useState("");
  const [spaceName, setSpaceName] = useState("General");
  const [spaceSlug, setSpaceSlug] = useState("general");
  const [planKey, setPlanKey] = useState("");
  const tenantSlugManual = useRef(false);
  const spaceSlugManual = useRef(false);
  const fingerprint = useRef("");
  const idempotencyKey = useRef("");

  useEffect(() => {
    const controller = new AbortController();
    requestJson<OnboardingCatalog>("/saas/onboarding/catalog", {
      cache: "no-cache",
      signal: controller.signal,
    })
      .then((value) => {
        setCatalog(value);
        setPlanKey(value.plans[0]?.key || "");
      })
      .catch((cause) => {
        if (!controller.signal.aborted) {
          setCatalogError(
            cause instanceof Error ? cause.message : t("error.generic"),
          );
        }
      });
    return () => controller.abort();
  }, [t]);

  function updateTenantName(value: string) {
    setTenantName(value);
    if (!tenantSlugManual.current) setTenantSlug(slugify(value));
  }

  function updateSpaceName(value: string) {
    setSpaceName(value);
    if (!spaceSlugManual.current) setSpaceSlug(slugify(value));
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!catalog || busy) return;
    const fields = new FormData(event.currentTarget);
    const body = {
      email: String(fields.get("email") || "")
        .trim()
        .toLowerCase(),
      display_name: String(fields.get("display_name") || "").trim() || null,
      tenant_name: tenantName.trim(),
      tenant_slug: tenantSlug.trim(),
      default_space_name: spaceName.trim(),
      default_space_slug: spaceSlug.trim(),
      plan_key: planKey,
      home_region: String(fields.get("home_region") || ""),
    };
    const nextFingerprint = JSON.stringify(body);
    if (fingerprint.current !== nextFingerprint) {
      fingerprint.current = nextFingerprint;
      idempotencyKey.current = newIdempotencyKey("signup");
    }
    setBusy(true);
    setError("");
    try {
      const result = await requestJson<RegistrationResponse>(
        "/saas/onboarding/registrations",
        mutation(body, idempotencyKey.current),
      );
      savePendingRegistration({
        email: body.email,
        registrationId: result.registration_id,
        verifyKey: newIdempotencyKey("verify"),
      });
      window.location.assign(
        `/signup/verify?registration_id=${encodeURIComponent(result.registration_id)}`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("error.generic"));
      setBusy(false);
    }
  }

  if (!catalog) {
    return (
      <div className="catalog-state" role="status">
        {catalogError || t("signup.loading")}
      </div>
    );
  }

  return (
    <form
      id="signup"
      className="signup-form"
      onSubmit={submit}
      aria-busy={busy}
    >
      <fieldset disabled={busy}>
        <legend>{t("signup.account")}</legend>
        <div className="signup-grid">
          <div className="signup-field">
            <Label htmlFor="email">{t("signup.email")}</Label>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              inputMode="email"
              autoCapitalize="none"
              spellCheck={false}
              required
              autoFocus
            />
          </div>
          <div className="signup-field">
            <Label htmlFor="display">
              {t("signup.name")} <span>{t("signup.optional")}</span>
            </Label>
            <Input id="display" name="display_name" autoComplete="name" />
          </div>
        </div>
      </fieldset>

      <fieldset disabled={busy}>
        <legend>{t("signup.workspace")}</legend>
        <div className="signup-grid">
          <div className="signup-field">
            <Label htmlFor="tenant-name">{t("signup.organizationName")}</Label>
            <Input
              id="tenant-name"
              maxLength={256}
              required
              value={tenantName}
              onChange={(event) => updateTenantName(event.target.value)}
            />
          </div>
          <div className="signup-field">
            <Label htmlFor="tenant-slug">{t("signup.organizationUrl")}</Label>
            <Input
              id="tenant-slug"
              pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
              required
              value={tenantSlug}
              onChange={(event) => {
                tenantSlugManual.current = true;
                setTenantSlug(event.target.value);
              }}
            />
          </div>
          <div className="signup-field">
            <Label htmlFor="space-name">{t("signup.firstSpace")}</Label>
            <Input
              id="space-name"
              required
              value={spaceName}
              onChange={(event) => updateSpaceName(event.target.value)}
            />
          </div>
          <div className="signup-field">
            <Label htmlFor="space-slug">{t("signup.spaceUrl")}</Label>
            <Input
              id="space-slug"
              pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
              required
              value={spaceSlug}
              onChange={(event) => {
                spaceSlugManual.current = true;
                setSpaceSlug(event.target.value);
              }}
            />
          </div>
        </div>
      </fieldset>

      <fieldset disabled={busy}>
        <legend>{t("signup.placement")}</legend>
        <div className="plan-grid">
          {catalog.plans.map((plan) => (
            <label className="plan-option" key={plan.key}>
              <input
                type="radio"
                name="plan"
                value={plan.key}
                checked={planKey === plan.key}
                onChange={() => setPlanKey(plan.key)}
              />
              <strong>
                {plan.key.charAt(0).toUpperCase() + plan.key.slice(1)}
              </strong>
              <small>
                {t("signup.planDetails", {
                  days: plan.trial_days,
                  runs: plan.trial_run_limit.toLocaleString(locale),
                  concurrency: plan.trial_concurrency_limit,
                })}
              </small>
            </label>
          ))}
        </div>
        <div className="signup-field">
          <Label htmlFor="region">{t("signup.homeRegion")}</Label>
          <select
            id="region"
            name="home_region"
            defaultValue={catalog.regions[0]}
          >
            {catalog.regions.map((region) => (
              <option value={region} key={region}>
                {region}
              </option>
            ))}
          </select>
        </div>
      </fieldset>

      {error ? (
        <p className="login-error" role="alert" tabIndex={-1}>
          {error}
        </p>
      ) : null}
      <Button type="submit" className="h-[52px] w-full" disabled={busy}>
        {busy ? (
          <LoaderCircle className="motion-safe:animate-spin" size={18} />
        ) : null}
        {busy ? t("signup.submitting") : t("signup.submit")}
        {!busy ? <ArrowRight size={18} aria-hidden="true" /> : null}
      </Button>
    </form>
  );
}
