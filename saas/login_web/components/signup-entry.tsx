import { useEffect, useState } from "react";
import { UserPlus } from "lucide-react";
import { FlowIntro } from "@/components/flow-intro";
import { SignupForm } from "@/components/signup-form";
import { FederatedSignIn } from "@/components/federated-sign-in";
import { Button } from "@/components/ui/button";
import {
  identityOptions,
  identityErrorKey,
  type IdentityOptions,
} from "@/lib/identity";
import { safeReturnTarget } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

export function SignupEntry() {
  const { t } = useI18n();
  const [options, setOptions] = useState<IdentityOptions | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState(0);
  const [destination, setDestination] = useState("/setup");
  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    setDestination(
      safeReturnTarget(
        new URLSearchParams(window.location.search).get("return_to") ||
          "/setup",
        window.location.origin,
      ),
    );
    identityOptions(controller.signal)
      .then(setOptions)
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause);
      });
    return () => controller.abort();
  }, [attempt]);
  const central = options !== null && options.mode !== "legacy";
  return (
    <>
      <FlowIntro
        step={1}
        icon={<UserPlus size={23} />}
        eyebrow={t("signup.eyebrow")}
        heading={t(central ? "identity.createAccount" : "signup.heading")}
        description={t(
          central ? "identity.registrationDescription" : "signup.description",
        )}
      />
      {options === null && error === null && (
        <p role="status">{t("identity.loading")}</p>
      )}
      {options !== null &&
        (central ? (
          <FederatedSignIn
            providers={options.providers}
            destination={destination}
            kind="signup"
          />
        ) : (
          <SignupForm />
        ))}
      {error !== null && (
        <div role="alert" className="login-error">
          <p>{t(identityErrorKey(error))}</p>
          <Button
            type="button"
            variant="ghost"
            onClick={() => setAttempt((value) => value + 1)}
          >
            {t("identity.retry")}
          </Button>
        </div>
      )}
      <noscript>
        <p className="login-error">{t("form.noScript")}</p>
      </noscript>
    </>
  );
}
