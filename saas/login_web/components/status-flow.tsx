"use client";

import { ArrowRight, Check, LoaderCircle, Rocket } from "lucide-react";
import { useEffect, useState } from "react";
import { FlowIntro } from "@/components/flow-intro";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/lib/i18n";
import { requestJson, type OnboardingStatus } from "@/lib/onboarding";

export function StatusFlow() {
  const { t } = useI18n();
  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stopped = false;
    let timer = 0;
    const controller = new AbortController();

    async function readStatus() {
      try {
        const value = await requestJson<OnboardingStatus>(
          "/saas/onboarding/status",
          { cache: "no-store", signal: controller.signal },
        );
        if (stopped) return;
        setStatus(value);
        setError("");
        if (["provisioning", "recovering"].includes(value.state)) {
          timer = window.setTimeout(readStatus, 2_000);
        }
      } catch (cause) {
        if (!stopped) {
          setError(cause instanceof Error ? cause.message : t("error.generic"));
        }
      }
    }

    void readStatus();
    return () => {
      stopped = true;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [t]);

  if (error) {
    return (
      <>
        <FlowIntro
          step={3}
          icon={<Rocket size={23} />}
          eyebrow={t("status.errorEyebrow")}
          heading={t("status.errorHeading")}
          description={t("status.errorDescription")}
        />
        <p className="login-error" role="alert">
          {error}
        </p>
        <Button asChild className="mt-4 h-[52px] w-full">
          <a href="/saas/login?return_to=%2Fsignup%2Fstatus">
            {t("status.signIn")} <ArrowRight size={18} aria-hidden="true" />
          </a>
        </Button>
      </>
    );
  }

  const complete = Boolean(
    status && ["ready_for_first_run", "complete"].includes(status.state),
  );
  const stages = [
    ["billing", t("status.billing")],
    ["runtime", t("status.runtime")],
    ["project", t("status.project")],
    ["activation", t("status.activation")],
    ["first_run", t("status.firstRun")],
  ] as const;
  const active = Math.max(
    0,
    stages.findIndex(([key]) => key === status?.stage),
  );

  return (
    <>
      <FlowIntro
        step={3}
        icon={
          status ? (
            complete ? (
              <Check size={23} />
            ) : (
              <Rocket size={23} />
            )
          ) : (
            <LoaderCircle className="motion-safe:animate-spin" size={23} />
          )
        }
        eyebrow={complete ? t("status.readyEyebrow") : t("status.eyebrow")}
        heading={complete ? t("status.readyHeading") : t("status.heading")}
        description={
          complete ? t("status.readyDescription") : t("status.description")
        }
      />
      {!status ? (
        <div className="catalog-state" role="status">
          {t("status.reading")}
        </div>
      ) : (
        <ol className="setup-progress">
          {stages.map(([, label], index) => {
            const done = complete || index < active;
            const current = !complete && index === active;
            return (
              <li
                className={done ? "done" : current ? "active" : ""}
                key={label}
              >
                <span>{done ? <Check size={15} /> : index + 1}</span>
                {label}
              </li>
            );
          })}
        </ol>
      )}
      {complete ? (
        <Button
          className="mt-6 h-[52px] w-full"
          onClick={() => window.location.assign("/")}
        >
          {t("status.open")} <ArrowRight size={18} aria-hidden="true" />
        </Button>
      ) : status ? (
        <p className="flow-footer-note">{t("status.continuing")}</p>
      ) : null}
    </>
  );
}
