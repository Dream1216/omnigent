"use client";

import { ArrowRight, LoaderCircle, MailCheck, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { FlowIntro } from "@/components/flow-intro";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { signIn } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";
import {
  clearPendingRegistration,
  mutation,
  newIdempotencyKey,
  readPendingRegistration,
  requestJson,
  savePendingRegistration,
  type PendingRegistration,
} from "@/lib/onboarding";

interface VerificationState {
  pending: PendingRegistration | null;
  registrationId: string;
  token: string | null;
}

export function VerificationFlow() {
  const { t } = useI18n();
  const [state, setState] = useState<VerificationState | null>(null);
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const token = fragment.get("token")?.trim() || null;
    if (window.location.hash) {
      window.history.replaceState(
        window.history.state,
        "",
        window.location.pathname + window.location.search,
      );
    }
    const pending = readPendingRegistration();
    const registrationId =
      params.get("registration_id") || pending?.registrationId || "";
    let matchingPending =
      pending?.registrationId === registrationId ? pending : null;
    if (token && registrationId && !matchingPending) {
      matchingPending = {
        registrationId,
        email: "",
        verifyKey: newIdempotencyKey("verify"),
      };
      savePendingRegistration(matchingPending);
    }
    setEmail(matchingPending?.email || "");
    setState({ pending: matchingPending, registrationId, token });
  }, []);

  const verifyKey = useMemo(() => {
    if (!state) return "";
    return state.pending?.verifyKey || newIdempotencyKey("verify");
  }, [state]);

  if (!state) {
    return <div className="catalog-state">{t("signup.loading")}</div>;
  }

  if (!state.registrationId) {
    return (
      <>
        <FlowIntro
          step={2}
          icon={<MailCheck size={23} />}
          eyebrow={t("verify.missingEyebrow")}
          heading={t("verify.missingHeading")}
          description={t("verify.missingDescription")}
        />
        <Button asChild className="h-[52px] w-full">
          <a href="/signup">{t("verify.startAgain")}</a>
        </Button>
      </>
    );
  }

  async function resend(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson(
        `/saas/onboarding/registrations/${encodeURIComponent(state!.registrationId)}/resend`,
        mutation(
          { email: email.trim().toLowerCase() },
          newIdempotencyKey("resend"),
        ),
      );
      savePendingRegistration({
        registrationId: state!.registrationId,
        email: email.trim().toLowerCase(),
        verifyKey: newIdempotencyKey("verify"),
      });
      setNotice(t("verify.resent"));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("error.generic"));
    } finally {
      setBusy(false);
    }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const current = state;
    if (busy || !current?.token) return;
    const fields = new FormData(event.currentTarget);
    const password = String(fields.get("password") || "");
    const confirmation = String(fields.get("confirmation") || "");
    if (password !== confirmation) {
      setError(t("verify.passwordMismatch"));
      return;
    }
    const normalizedEmail = email.trim().toLowerCase();
    savePendingRegistration({
      registrationId: current.registrationId,
      email: normalizedEmail,
      verifyKey,
    });
    setBusy(true);
    setError("");
    try {
      await requestJson(
        `/saas/onboarding/registrations/${encodeURIComponent(current.registrationId)}/verify`,
        mutation({ verification_token: current.token, password }, verifyKey),
      );
      const controller = new AbortController();
      await signIn(normalizedEmail, password, controller.signal);
      clearPendingRegistration();
      window.location.replace("/signup/status");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("error.generic"));
      setBusy(false);
    }
  }

  if (!state.token) {
    return (
      <>
        <FlowIntro
          step={2}
          icon={<MailCheck size={23} />}
          eyebrow={t("verify.checkEyebrow")}
          heading={t("verify.checkHeading")}
          description={t("verify.checkDescription")}
        />
        <form className="compact-flow-form" onSubmit={resend} aria-busy={busy}>
          <div className="signup-field">
            <Label htmlFor="email">{t("signup.email")}</Label>
            <Input
              id="email"
              name="email"
              type="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </div>
          {notice ? (
            <p className="flow-notice" role="status">
              {notice}
            </p>
          ) : null}
          {error ? (
            <p className="login-error" role="alert">
              {error}
            </p>
          ) : null}
          <Button type="submit" className="h-[52px] w-full" disabled={busy}>
            {busy ? (
              <LoaderCircle className="motion-safe:animate-spin" size={18} />
            ) : null}
            {busy ? t("verify.resending") : t("verify.resend")}
          </Button>
        </form>
      </>
    );
  }

  return (
    <>
      <FlowIntro
        step={2}
        icon={<ShieldCheck size={23} />}
        eyebrow={t("verify.secureEyebrow")}
        heading={t("verify.secureHeading")}
        description={t("verify.secureDescription")}
      />
      <form className="compact-flow-form" onSubmit={verify} aria-busy={busy}>
        <div className="signup-field">
          <Label htmlFor="email">{t("signup.email")}</Label>
          <Input
            id="email"
            name="email"
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </div>
        <div className="signup-field">
          <Label htmlFor="password">{t("verify.password")}</Label>
          <Input
            id="password"
            name="password"
            type="password"
            minLength={12}
            autoComplete="new-password"
            placeholder={t("verify.passwordPlaceholder")}
            required
          />
        </div>
        <div className="signup-field">
          <Label htmlFor="confirmation">{t("verify.confirm")}</Label>
          <Input
            id="confirmation"
            name="confirmation"
            type="password"
            minLength={12}
            autoComplete="new-password"
            placeholder={t("verify.confirmPlaceholder")}
            required
          />
        </div>
        {error ? (
          <p className="login-error" role="alert">
            {error}
          </p>
        ) : null}
        <Button type="submit" className="h-[52px] w-full" disabled={busy}>
          {busy ? (
            <LoaderCircle className="motion-safe:animate-spin" size={18} />
          ) : null}
          {busy ? t("verify.submitting") : t("verify.submit")}
          {!busy ? <ArrowRight size={18} aria-hidden="true" /> : null}
        </Button>
      </form>
    </>
  );
}
