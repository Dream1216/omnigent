"use client";

import { Check, Link2, LoaderCircle, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  identityOptions,
  identityJson,
  identityErrorKey,
  IdentityError,
  linkIdentity,
  logoutIdentity,
  reauthenticatePath,
  type IdentityOptions,
  type IdentityConnection,
  type IdentityConflict,
} from "@/lib/identity";
import { useI18n } from "@/lib/i18n";

interface AccountState {
  userId: string;
  options: IdentityOptions;
  connections: IdentityConnection[];
  conflicts: IdentityConflict[];
}

export function IdentitySettings() {
  const { locale, t } = useI18n();
  const [account, setAccount] = useState<AccountState | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [signedOut, setSignedOut] = useState(false);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const pending = useRef(false);
  const errorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    Promise.all([
      identityJson<{ authenticated: boolean; user_id: string }>(
        "/saas/auth/bootstrap",
        { signal: controller.signal },
      ),
      identityOptions(controller.signal),
      identityJson<IdentityConnection[]>("/saas/identities", {
        signal: controller.signal,
      }),
      identityJson<IdentityConflict[]>("/saas/auth/identity-conflicts", {
        signal: controller.signal,
      }),
    ])
      .then(([session, options, connections, conflicts]) => {
        if (controller.signal.aborted) return;
        if (!session.authenticated || typeof session.user_id !== "string") {
          setSignedOut(true);
          return;
        }
        if (!Array.isArray(connections) || !Array.isArray(conflicts))
          throw new IdentityError("invalid_response");
        setAccount({
          userId: session.user_id,
          options,
          connections,
          conflicts,
        });
      })
      .catch((cause) => {
        if (controller.signal.aborted) return;
        if (cause instanceof IdentityError && cause.status === 401)
          setSignedOut(true);
        else setError(cause);
      });
    return () => controller.abort();
  }, [attempt]);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  async function connect(provider: IdentityOptions["providers"][number]) {
    if (!consent || pending.current) return;
    pending.current = true;
    setBusy(true);
    setError(null);
    try {
      window.location.assign(await linkIdentity(provider, locale));
    } catch (cause) {
      setError(cause);
      pending.current = false;
      setBusy(false);
    }
  }

  async function signOut() {
    if (!account || pending.current) return;
    pending.current = true;
    setBusy(true);
    setError(null);
    try {
      window.location.assign(await logoutIdentity(account.options));
    } catch (cause) {
      setError(cause);
      pending.current = false;
      setBusy(false);
    }
  }

  if (signedOut)
    return (
      <div className="identity-callout">
        <ShieldCheck size={24} aria-hidden="true" />
        <h2>{t("identity.signInFirst")}</h2>
        <p>{t("identity.signInFirstDescription")}</p>
        <Button asChild>
          <a href={reauthenticatePath(locale)}>{t("identity.signInAgain")}</a>
        </Button>
      </div>
    );

  return (
    <div className="identity-settings">
      {!account && !error && (
        <p role="status" className="identity-caption">
          <LoaderCircle className="motion-safe:animate-spin" size={18} />
          {t("identity.loading")}
        </p>
      )}
      {account && (
        <>
          <div className="identity-account">
            <span>{t("identity.currentAccount")}</span>
            <code>{account.userId}</code>
          </div>
          <section aria-labelledby="sign-in-methods">
            <h2 id="sign-in-methods">{t("identity.methods")}</h2>
            <ul className="identity-methods">
              {account.connections
                .filter((connection) => connection.status === "active")
                .map((connection) => (
                  <li key={connection.id}>
                    <span className="identity-method-icon">
                      <Check size={17} aria-hidden="true" />
                    </span>
                    <div>
                      <strong>
                        {connection.email_normalized ||
                          connection.phone_e164 ||
                          connection.provider}
                      </strong>
                      <small>
                        {connection.provider === "casdoor"
                          ? t("identity.central")
                          : connection.provider}
                        {connection.email_verified
                          ? " · " + t("identity.verified")
                          : connection.phone_verified
                            ? " · " + t("identity.verifiedPhone")
                            : ""}
                      </small>
                    </div>
                  </li>
                ))}
            </ul>
          </section>
          {account.conflicts.length > 0 && (
            <section
              className="identity-callout"
              aria-labelledby="identity-review"
            >
              <h2 id="identity-review">{t("identity.confirmationHeading")}</h2>
              <p>{t("identity.confirmationDescription")}</p>
              <ul>
                {account.conflicts.map((conflict) => (
                  <li key={conflict.id}>
                    <strong>{conflict.email}</strong>
                  </li>
                ))}
              </ul>
            </section>
          )}
          <section aria-labelledby="identity-connect">
            <h2 id="identity-connect">
              <Link2 size={18} aria-hidden="true" />
              {t("identity.connectHeading")}
            </h2>
            {account.options.providers.length === 0 ? (
              <p className="identity-caption">{t("identity.noProviders")}</p>
            ) : (
              <>
                <p className="identity-caption">
                  {t("identity.connectDescription")}
                </p>
                <label className="identity-consent">
                  <input
                    type="checkbox"
                    checked={consent}
                    onChange={(event) => setConsent(event.target.checked)}
                    disabled={busy}
                  />
                  <span>{t("identity.consent")}</span>
                </label>
                {account.options.providers.map((provider) => (
                  <Button
                    key={provider.name}
                    type="button"
                    disabled={!consent || busy}
                    onClick={() => void connect(provider)}
                  >
                    {busy ? (
                      <LoaderCircle
                        size={18}
                        className="motion-safe:animate-spin"
                        aria-hidden="true"
                      />
                    ) : (
                      <Link2 size={18} aria-hidden="true" />
                    )}
                    {t(busy ? "identity.connecting" : "identity.connect")}
                  </Button>
                ))}
                <p className="identity-caption identity-reauth">
                  <a href={reauthenticatePath(locale)}>
                    {t("identity.signInAgain")}
                  </a>
                </p>
              </>
            )}
          </section>
        </>
      )}
      {account && (
        <Button
          type="button"
          variant="ghost"
          disabled={busy}
          onClick={() => void signOut()}
        >
          {t("identity.signOut")}
        </Button>
      )}
      {error !== null && (
        <div
          className="login-error"
          role="alert"
          aria-label={t("identity.errorTitle")}
          ref={errorRef}
          tabIndex={-1}
        >
          <p>{t(identityErrorKey(error))}</p>
          <div className="identity-actions">
            <Button asChild variant="ghost">
              <a href={reauthenticatePath(locale)}>
                {t("identity.signInAgain")}
              </a>
            </Button>
            {!account && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => setAttempt((value) => value + 1)}
              >
                {t("identity.retry")}
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
