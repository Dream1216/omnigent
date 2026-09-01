import { useRef, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Check, Cloud, RefreshCw, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { fetchOnboardingCatalog, requestOnboardingRegistration } from "@/lib/saasOnboardingApi";
import {
  humanizeCatalogKey,
  onboardingErrorMessage,
  slugifyOnboardingName,
  TENANT_SLUG_PATTERN,
} from "@/lib/saasOnboardingPresentation";
import { storePendingOnboardingRegistration } from "@/lib/saasOnboardingState";
import { Link, useNavigate } from "@/lib/routing";
import { cn } from "@/lib/utils";
import { SaasAuthShell } from "./SaasAuthShell";

interface SignupForm {
  email: string;
  displayName: string;
  tenantName: string;
  tenantSlug: string;
  spaceName: string;
  spaceSlug: string;
  planKey: string;
  homeRegion: string;
}

const INITIAL_FORM: SignupForm = {
  email: "",
  displayName: "",
  tenantName: "",
  tenantSlug: "",
  spaceName: "General",
  spaceSlug: "general",
  planKey: "",
  homeRegion: "",
};

function newIdempotencyKey(): string {
  return `signup-${crypto.randomUUID()}`;
}

export function SaasSignupPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState(INITIAL_FORM);
  const [tenantSlugManual, setTenantSlugManual] = useState(false);
  const [spaceSlugManual, setSpaceSlugManual] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestIdentity = useRef<{ fingerprint: string; key: string } | null>(null);
  const catalog = useQuery({
    queryKey: ["saas-onboarding-catalog"],
    queryFn: fetchOnboardingCatalog,
    staleTime: 60_000,
    retry: 1,
  });

  const selectedPlan = form.planKey || catalog.data?.plans[0]?.key || "";
  const selectedRegion = form.homeRegion || catalog.data?.regions[0] || "";

  function update<K extends keyof SignupForm>(key: K, value: SignupForm[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setError(null);
  }

  function updateTenantName(value: string) {
    setForm((current) => ({
      ...current,
      tenantName: value,
      tenantSlug: tenantSlugManual ? current.tenantSlug : slugifyOnboardingName(value),
    }));
    setError(null);
  }

  function updateSpaceName(value: string) {
    setForm((current) => ({
      ...current,
      spaceName: value,
      spaceSlug: spaceSlugManual ? current.spaceSlug : slugifyOnboardingName(value),
    }));
    setError(null);
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting || !catalog.data) return;
    const normalized = {
      ...form,
      email: form.email.trim().toLowerCase(),
      displayName: form.displayName.trim(),
      tenantName: form.tenantName.trim(),
      tenantSlug: form.tenantSlug.trim(),
      spaceName: form.spaceName.trim(),
      spaceSlug: form.spaceSlug.trim(),
      planKey: selectedPlan,
      homeRegion: selectedRegion,
    };
    if (!TENANT_SLUG_PATTERN.test(normalized.tenantSlug)) {
      setError("Organization URL must use lowercase letters, numbers, and single hyphens.");
      document.getElementById("signup-tenant-slug")?.focus();
      return;
    }
    if (!TENANT_SLUG_PATTERN.test(normalized.spaceSlug)) {
      setError("Space URL must use lowercase letters, numbers, and single hyphens.");
      document.getElementById("signup-space-slug")?.focus();
      return;
    }
    const fingerprint = JSON.stringify(normalized);
    if (requestIdentity.current?.fingerprint !== fingerprint) {
      requestIdentity.current = { fingerprint, key: newIdempotencyKey() };
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await requestOnboardingRegistration(
        {
          email: normalized.email,
          displayName: normalized.displayName || null,
          tenantName: normalized.tenantName,
          tenantSlug: normalized.tenantSlug,
          defaultSpaceName: normalized.spaceName,
          defaultSpaceSlug: normalized.spaceSlug,
          planKey: normalized.planKey,
          homeRegion: normalized.homeRegion,
        },
        requestIdentity.current.key,
      );
      storePendingOnboardingRegistration({
        registrationId: result.registrationId,
        email: normalized.email,
      });
      navigate(`/signup/verify?registration_id=${encodeURIComponent(result.registrationId)}`);
    } catch (cause) {
      setError(onboardingErrorMessage(cause));
      setSubmitting(false);
      if (
        cause instanceof Error &&
        (cause.message.includes("plan") || cause.message.includes("region"))
      ) {
        void catalog.refetch();
      }
    }
  }

  return (
    <SaasAuthShell
      eyebrow="Start your trial"
      title="Create your organization"
      description="Choose the workspace boundary, plan, and home region that your team will start with."
      step={{ current: 1, total: 3, label: "Workspace details" }}
      footer={
        <>
          Already have a workspace?{" "}
          <Link
            to="/saas/login"
            className="font-medium text-foreground underline decoration-primary/40 underline-offset-4 hover:decoration-primary"
            componentId="saas_signup.sign_in"
          >
            Sign in
          </Link>
        </>
      }
    >
      {catalog.isPending ? (
        <div
          className="grid min-h-48 place-items-center text-sm text-muted-foreground"
          role="status"
        >
          Loading available plans and regions…
        </div>
      ) : catalog.isError || !catalog.data ? (
        <Alert variant="destructive">
          <Cloud className="size-4" />
          <AlertTitle>Registration is not available</AlertTitle>
          <AlertDescription className="mt-1">
            We could not load the current plan and region catalog.
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => void catalog.refetch()}
              componentId="saas_signup.retry_catalog"
            >
              <RefreshCw data-icon="inline-start" />
              Try again
            </Button>
          </AlertDescription>
        </Alert>
      ) : (
        <form onSubmit={onSubmit} className="space-y-8">
          <fieldset className="space-y-4">
            <legend className="flex items-center gap-2 text-sm font-semibold">
              <span className="grid size-6 place-items-center rounded-full bg-primary/10 font-mono text-[11px] text-primary">
                01
              </span>
              Your account
            </legend>
            <div className="grid gap-4 sm:grid-cols-2">
              <FormField label="Work email" htmlFor="signup-email">
                <Input
                  id="signup-email"
                  className="h-11"
                  type="email"
                  inputMode="email"
                  autoCapitalize="none"
                  autoComplete="email"
                  autoFocus
                  required
                  value={form.email}
                  onChange={(event) => update("email", event.target.value)}
                  disabled={submitting}
                />
              </FormField>
              <FormField label="Your name" htmlFor="signup-display-name" optional>
                <Input
                  id="signup-display-name"
                  className="h-11"
                  autoComplete="name"
                  value={form.displayName}
                  onChange={(event) => update("displayName", event.target.value)}
                  disabled={submitting}
                />
              </FormField>
            </div>
          </fieldset>

          <fieldset className="space-y-4 border-t border-border/70 pt-7">
            <legend className="flex translate-y-3 items-center gap-2 bg-card pr-3 text-sm font-semibold">
              <span className="grid size-6 place-items-center rounded-full bg-primary/10 font-mono text-[11px] text-primary">
                02
              </span>
              Workspace
            </legend>
            <div className="grid gap-4 sm:grid-cols-2">
              <FormField label="Organization name" htmlFor="signup-tenant-name">
                <Input
                  id="signup-tenant-name"
                  className="h-11"
                  required
                  maxLength={256}
                  value={form.tenantName}
                  onChange={(event) => updateTenantName(event.target.value)}
                  disabled={submitting}
                />
              </FormField>
              <FormField
                label="Organization URL"
                htmlFor="signup-tenant-slug"
                hint="Lowercase letters, numbers, and hyphens"
              >
                <Input
                  id="signup-tenant-slug"
                  className="h-11 font-mono text-sm"
                  required
                  maxLength={63}
                  pattern={TENANT_SLUG_PATTERN.source}
                  value={form.tenantSlug}
                  onChange={(event) => {
                    setTenantSlugManual(true);
                    update("tenantSlug", slugifyOnboardingName(event.target.value));
                  }}
                  disabled={submitting}
                />
              </FormField>
              <FormField label="First space" htmlFor="signup-space-name">
                <Input
                  id="signup-space-name"
                  className="h-11"
                  required
                  maxLength={256}
                  value={form.spaceName}
                  onChange={(event) => updateSpaceName(event.target.value)}
                  disabled={submitting}
                />
              </FormField>
              <FormField label="Space URL" htmlFor="signup-space-slug">
                <Input
                  id="signup-space-slug"
                  className="h-11 font-mono text-sm"
                  required
                  maxLength={63}
                  pattern={TENANT_SLUG_PATTERN.source}
                  value={form.spaceSlug}
                  onChange={(event) => {
                    setSpaceSlugManual(true);
                    update("spaceSlug", slugifyOnboardingName(event.target.value));
                  }}
                  disabled={submitting}
                />
              </FormField>
            </div>
          </fieldset>

          <fieldset className="space-y-4 border-t border-border/70 pt-7">
            <legend className="flex translate-y-3 items-center gap-2 bg-card pr-3 text-sm font-semibold">
              <span className="grid size-6 place-items-center rounded-full bg-primary/10 font-mono text-[11px] text-primary">
                03
              </span>
              Plan and home region
            </legend>
            <div className="grid gap-3 sm:grid-cols-2">
              {catalog.data.plans.map((plan) => {
                const checked = selectedPlan === plan.key;
                return (
                  <label
                    key={plan.key}
                    className={cn(
                      "relative cursor-pointer rounded-xl border p-4 transition-colors focus-within:ring-3 focus-within:ring-ring/40",
                      checked
                        ? "border-primary/60 bg-primary/[0.06]"
                        : "border-border hover:border-foreground/25",
                    )}
                  >
                    <input
                      className="sr-only"
                      type="radio"
                      name="plan"
                      value={plan.key}
                      checked={checked}
                      onChange={() => update("planKey", plan.key)}
                      disabled={submitting}
                    />
                    <span className="flex items-start justify-between gap-3">
                      <span>
                        <span className="block font-semibold">{humanizeCatalogKey(plan.key)}</span>
                        <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                          {plan.trialDays}-day trial · {plan.trialRunLimit.toLocaleString()} runs
                        </span>
                        <span className="block text-xs leading-5 text-muted-foreground">
                          Up to {plan.trialConcurrencyLimit} concurrent
                        </span>
                      </span>
                      <span
                        className={cn(
                          "grid size-5 place-items-center rounded-full border",
                          checked
                            ? "border-primary bg-primary text-primary-foreground"
                            : "border-border",
                        )}
                        aria-hidden="true"
                      >
                        {checked ? <Check className="size-3" /> : null}
                      </span>
                    </span>
                  </label>
                );
              })}
            </div>
            <FormField
              label="Home region"
              htmlFor="signup-region"
              hint="New workloads start in this data region."
            >
              <select
                id="signup-region"
                className="h-11 w-full rounded-lg border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={selectedRegion}
                onChange={(event) => update("homeRegion", event.target.value)}
                disabled={submitting}
                required
              >
                {catalog.data.regions.map((region) => (
                  <option key={region} value={region}>
                    {humanizeCatalogKey(region)} ({region})
                  </option>
                ))}
              </select>
            </FormField>
          </fieldset>

          {error ? (
            <Alert variant="destructive">
              <ShieldCheck className="size-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-col-reverse gap-3 border-t border-border/70 pt-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="max-w-sm text-xs leading-5 text-muted-foreground">
              By continuing, you confirm you are authorized to create this organization.
            </p>
            <Button
              type="submit"
              size="lg"
              className="h-11 min-w-40"
              loading={submitting}
              disabled={
                !form.email.trim() ||
                !form.tenantName.trim() ||
                !form.tenantSlug ||
                !form.spaceName.trim() ||
                !form.spaceSlug ||
                !selectedPlan ||
                !selectedRegion
              }
              componentId="saas_signup.submit"
            >
              Continue
              <ArrowRight data-icon="inline-end" />
            </Button>
          </div>
        </form>
      )}
    </SaasAuthShell>
  );
}

function FormField({
  label,
  htmlFor,
  hint,
  optional = false,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  optional?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between gap-3">
        <label htmlFor={htmlFor} className="text-sm font-medium">
          {label}
        </label>
        {optional ? <span className="text-xs text-muted-foreground">Optional</span> : null}
      </div>
      {children}
      {hint ? <p className="text-xs leading-5 text-muted-foreground">{hint}</p> : null}
    </div>
  );
}
