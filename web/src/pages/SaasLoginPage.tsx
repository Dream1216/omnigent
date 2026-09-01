import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, KeyRound } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { sanitizeAuthReturnTo } from "@/lib/authNavigation";
import { fetchOnboardingCatalog, loginSaas } from "@/lib/saasOnboardingApi";
import { onboardingErrorMessage } from "@/lib/saasOnboardingPresentation";
import { Link, useSearchParams } from "@/lib/routing";
import { SaasAuthShell } from "./SaasAuthShell";

export function SaasLoginPage() {
  const [params] = useSearchParams();
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const returnTo = sanitizeAuthReturnTo(params.get("return_to"));
  const catalog = useQuery({
    queryKey: ["saas-onboarding-catalog"],
    queryFn: fetchOnboardingCatalog,
    staleTime: 60_000,
    retry: 1,
  });

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      await loginSaas(email.trim().toLowerCase(), password);
      window.location.assign(returnTo);
    } catch (cause) {
      setError(onboardingErrorMessage(cause));
      setSubmitting(false);
    }
  }

  return (
    <SaasAuthShell
      compact
      eyebrow="Welcome back"
      title="Sign in to your workspace"
      description="Use the work email and password connected to your organization."
      footer={
        catalog.isSuccess ? (
          <>
            New to Omnigent?{" "}
            <Link
              to="/signup"
              className="font-medium text-foreground underline decoration-primary/40 underline-offset-4 hover:decoration-primary"
              componentId="saas_login.create_workspace"
            >
              Create a workspace
            </Link>
          </>
        ) : null
      }
    >
      <form className="space-y-5" onSubmit={onSubmit}>
        <div className="space-y-2">
          <label htmlFor="saas-login-email" className="text-sm font-medium">
            Work email
          </label>
          <Input
            id="saas-login-email"
            className="h-11"
            type="email"
            inputMode="email"
            autoCapitalize="none"
            autoComplete="email"
            autoFocus
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={submitting}
          />
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-3">
            <label htmlFor="saas-login-password" className="text-sm font-medium">
              Password
            </label>
          </div>
          <Input
            id="saas-login-password"
            className="h-11"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={submitting}
          />
        </div>

        {error ? (
          <Alert variant="destructive">
            <KeyRound className="size-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        <Button
          type="submit"
          size="lg"
          className="h-11 w-full"
          loading={submitting}
          disabled={email.trim() === "" || password === ""}
          componentId="saas_login.submit"
        >
          Sign in
          <ArrowRight data-icon="inline-end" />
        </Button>
      </form>
    </SaasAuthShell>
  );
}
