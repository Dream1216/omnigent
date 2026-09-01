import { useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { ArrowLeft, ArrowRight, CheckCircle2, Mail, RotateCcw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  loginSaas,
  OnboardingApiError,
  resendOnboardingVerification,
  verifyOnboardingRegistration,
} from "@/lib/saasOnboardingApi";
import { consumeVerificationToken, onboardingErrorMessage } from "@/lib/saasOnboardingPresentation";
import {
  clearPendingOnboardingRegistration,
  readPendingOnboardingRegistration,
  storePendingOnboardingRegistration,
} from "@/lib/saasOnboardingState";
import { Link, useNavigate, useSearchParams } from "@/lib/routing";
import { SaasAuthShell } from "./SaasAuthShell";

const MIN_PASSWORD_LENGTH = 12;

function newIdempotencyKey(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

export function SaasVerificationPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const pending = readPendingOnboardingRegistration();
  const registrationId = params.get("registration_id")?.trim() || pending?.registrationId || "";
  const [token, setToken] = useState<string | null>(null);
  const [tokenReady, setTokenReady] = useState(false);
  const [email, setEmail] = useState(pending?.email ?? "");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [verified, setVerified] = useState(false);
  const [resent, setResent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const verifyKey = useRef(newIdempotencyKey("verify"));
  const resendKey = useRef(newIdempotencyKey("resend"));

  useLayoutEffect(() => {
    setToken(consumeVerificationToken());
    setTokenReady(true);
  }, []);

  async function onVerify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting || token === null || registrationId === "") return;
    setError(null);
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      document.getElementById("saas-verify-password")?.focus();
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      document.getElementById("saas-verify-confirm")?.focus();
      return;
    }
    setSubmitting(true);
    try {
      await verifyOnboardingRegistration(registrationId, token, password, verifyKey.current);
      setVerified(true);
      setToken(null);
      try {
        await loginSaas(email.trim().toLowerCase(), password);
        clearPendingOnboardingRegistration();
        navigate("/signup/status", { replace: true });
      } catch {
        setError("Your workspace was created, but automatic sign-in did not complete.");
        setSubmitting(false);
      }
    } catch (cause) {
      setError(onboardingErrorMessage(cause));
      setSubmitting(false);
    }
  }

  async function onResend(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting || registrationId === "") return;
    setSubmitting(true);
    setError(null);
    try {
      await resendOnboardingVerification(
        registrationId,
        email.trim().toLowerCase(),
        resendKey.current,
      );
      storePendingOnboardingRegistration({ registrationId, email: email.trim().toLowerCase() });
      setResent(true);
    } catch (cause) {
      setError(onboardingErrorMessage(cause));
      if (cause instanceof OnboardingApiError && cause.code === "identity_confirmation_required") {
        clearPendingOnboardingRegistration();
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (!tokenReady) return null;

  if (registrationId === "") {
    return (
      <SaasAuthShell
        compact
        eyebrow="Verification"
        title="Open your registration link"
        description="The registration reference is missing from this page. Start again to create a new workspace."
        step={{ current: 2, total: 3, label: "Verify email" }}
      >
        <Button asChild size="lg" className="h-11 w-full">
          <Link to="/signup" componentId="saas_verify.restart">
            <ArrowLeft data-icon="inline-start" />
            Start again
          </Link>
        </Button>
      </SaasAuthShell>
    );
  }

  if (token === null || verified) {
    return (
      <SaasAuthShell
        compact
        eyebrow={verified ? "Workspace created" : "Check your inbox"}
        title={verified ? "Sign in to continue" : "Verify your work email"}
        description={
          verified
            ? "Your email is verified and your organization is being prepared. Sign in to follow its progress."
            : "Use the secure link in the verification email. If it has expired or did not arrive, request another one below."
        }
        step={{ current: 2, total: 3, label: "Verify email" }}
        footer={
          <Link
            to="/signup"
            className="font-medium text-foreground underline decoration-primary/40 underline-offset-4"
            componentId="saas_verify.change_registration"
          >
            Use a different email
          </Link>
        }
      >
        {verified ? (
          <div className="space-y-4">
            <Alert>
              <CheckCircle2 className="size-4 text-primary" />
              <AlertTitle>Verification complete</AlertTitle>
              <AlertDescription>
                Your workspace setup is continuing safely in the background.
              </AlertDescription>
            </Alert>
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            <Button asChild size="lg" className="h-11 w-full">
              <Link
                to={`/saas/login?email=${encodeURIComponent(email)}&return_to=${encodeURIComponent("/signup/status")}`}
                componentId="saas_verify.sign_in"
              >
                Sign in
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
          </div>
        ) : (
          <form onSubmit={onResend} className="space-y-5">
            {resent ? (
              <Alert>
                <Mail className="size-4 text-primary" />
                <AlertTitle>Verification email requested</AlertTitle>
                <AlertDescription>
                  If this address can receive mail, a new secure link is on its way.
                </AlertDescription>
              </Alert>
            ) : null}
            <div className="space-y-2">
              <label htmlFor="saas-resend-email" className="text-sm font-medium">
                Work email
              </label>
              <Input
                id="saas-resend-email"
                className="h-11"
                type="email"
                inputMode="email"
                autoCapitalize="none"
                autoComplete="email"
                required
                value={email}
                onChange={(event) => {
                  setEmail(event.target.value);
                  setResent(false);
                  setError(null);
                }}
                disabled={submitting}
              />
            </div>
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            <Button
              type="submit"
              variant="outline"
              size="lg"
              className="h-11 w-full"
              loading={submitting}
              disabled={!email.trim()}
              componentId="saas_verify.resend"
            >
              <RotateCcw data-icon="inline-start" />
              Send another email
            </Button>
          </form>
        )}
      </SaasAuthShell>
    );
  }

  return (
    <SaasAuthShell
      compact
      eyebrow="Email verified"
      title="Secure your account"
      description="Choose the password you will use to sign in to this organization."
      step={{ current: 2, total: 3, label: "Verify email" }}
    >
      <form onSubmit={onVerify} className="space-y-5">
        <div className="space-y-2">
          <label htmlFor="saas-verify-email" className="text-sm font-medium">
            Work email
          </label>
          <Input
            id="saas-verify-email"
            className="h-11"
            type="email"
            inputMode="email"
            autoCapitalize="none"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={submitting}
          />
        </div>
        <div className="space-y-2">
          <label htmlFor="saas-verify-password" className="text-sm font-medium">
            Password
          </label>
          <Input
            id="saas-verify-password"
            className="h-11"
            type="password"
            autoComplete="new-password"
            minLength={MIN_PASSWORD_LENGTH}
            required
            aria-describedby="saas-password-hint"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              setError(null);
            }}
            disabled={submitting}
          />
          <p id="saas-password-hint" className="text-xs text-muted-foreground">
            At least {MIN_PASSWORD_LENGTH} characters.
          </p>
        </div>
        <div className="space-y-2">
          <label htmlFor="saas-verify-confirm" className="text-sm font-medium">
            Confirm password
          </label>
          <Input
            id="saas-verify-confirm"
            className="h-11"
            type="password"
            autoComplete="new-password"
            minLength={MIN_PASSWORD_LENGTH}
            required
            value={confirm}
            onChange={(event) => {
              setConfirm(event.target.value);
              setError(null);
            }}
            disabled={submitting}
          />
        </div>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        <Button
          type="submit"
          size="lg"
          className="h-11 w-full"
          loading={submitting}
          disabled={!email.trim() || password.length < MIN_PASSWORD_LENGTH || confirm === ""}
          componentId="saas_verify.submit"
        >
          Verify and continue
          <ArrowRight data-icon="inline-end" />
        </Button>
      </form>
    </SaasAuthShell>
  );
}
