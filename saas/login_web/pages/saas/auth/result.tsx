import { useEffect, useState } from "react";
import Head from "next/head";
import { AlertCircle, LoaderCircle, ShieldCheck } from "lucide-react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/ui/button";
import { persistCsrfToken, safeReturnTarget } from "@/lib/auth";
import { reauthenticatePath } from "@/lib/identity";
import { useI18n, type MessageKey } from "@/lib/i18n";

export default function OidcResultPage() {
  const { locale, t } = useI18n();
  const [state, setState] = useState("pending");
  useEffect(() => {
    const payload = document.getElementById("oidc-result");
    if (!payload) {
      setState("retry");
      return;
    }
    try {
      const value = JSON.parse(payload.textContent || "{}");
      window.history.replaceState(
        window.history.state,
        "",
        "/saas/auth/result",
      );
      if (value.error_code) {
        setState(String(value.error_code));
        return;
      }
      if (typeof value.csrf_token !== "string" || !value.csrf_token) {
        setState("retry");
        return;
      }
      try {
        persistCsrfToken(value.csrf_token);
      } catch {
        setState("storage");
        return;
      }
      // The return target was validated and persisted with the one-time transaction.
      window.location.replace(
        safeReturnTarget(value.return_to, window.location.origin),
      );
    } catch {
      setState("retry");
    }
  }, []);
  const conflict = state === "identity_confirmation_required";
  const pending = state === "pending";
  const message: MessageKey = conflict
    ? "identity.conflictDescription"
    : state === "storage"
      ? "identity.storageError"
      : state === "oidc_dependency_unavailable"
        ? "error.unavailable"
        : state === "reauthentication_identity_mismatch"
          ? "identity.wrongAccount"
          : state === "identity_conflict_rejected"
            ? "identity.rejected"
            : state === "identity_conflict_manual_review_required"
              ? "identity.manualReview"
              : pending
                ? "identity.completing"
                : "identity.retryDescription";
  const heading = t(
    conflict
      ? "identity.conflictHeading"
      : pending
        ? "identity.completingHeading"
        : "identity.retryHeading",
  );
  return (
    <>
      <Head>
        <title>{heading} · 胜天半子</title>
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <AuthShell
        headingId="result-title"
        linkHref="/saas/account/identities"
        linkLabel={t("identity.title")}
        prompt=""
        skipHref="#result-title"
        skipLabel={heading}
        contentClassName="flow-content"
      >
        <div className="welcome-mark" aria-hidden="true">
          {pending ? (
            <LoaderCircle size={23} className="motion-safe:animate-spin" />
          ) : conflict ? (
            <ShieldCheck size={23} />
          ) : (
            <AlertCircle size={23} />
          )}
        </div>
        <p className="eyebrow">{t("identity.eyebrow")}</p>
        <h1 id="result-title">
          {heading}
          <span>.</span>
        </h1>
        <p id="status" role="status" className="login-description">
          {t(message)}
        </p>
        {!pending && (
          <div className="identity-actions">
            <Button asChild>
              <a href={reauthenticatePath(locale)}>
                {t(
                  conflict
                    ? "identity.existingAccount"
                    : "identity.signInAgain",
                )}
              </a>
            </Button>
            {conflict && (
              <Button variant="ghost" asChild>
                <a href="/saas/account/identities">{t("identity.title")}</a>
              </Button>
            )}
          </div>
        )}
        <noscript>
          <p className="login-error">{t("form.noScript")}</p>
          <a href="/saas/login">{t("signup.signIn")}</a>
        </noscript>
      </AuthShell>
    </>
  );
}
