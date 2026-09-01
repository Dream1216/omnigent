import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, Check, Clock3, Copy, LifeBuoy, RotateCcw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { fetchOnboardingStatus, OnboardingApiError } from "@/lib/saasOnboardingApi";
import {
  onboardingErrorMessage,
  onboardingStageIndex,
  ONBOARDING_STAGES,
} from "@/lib/saasOnboardingPresentation";
import { Link } from "@/lib/routing";
import { cn } from "@/lib/utils";
import { SaasAuthShell } from "./SaasAuthShell";

export function SaasOnboardingStatusPage() {
  const [copied, setCopied] = useState(false);
  const status = useQuery({
    queryKey: ["saas-onboarding-status"],
    queryFn: fetchOnboardingStatus,
    retry: 1,
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return state === "provisioning" || state === "recovering" ? 2_000 : false;
    },
  });

  const current = status.data;
  const complete = current?.state === "ready_for_first_run" || current?.state === "complete";
  const supportRequired = current?.state === "support_required";
  const activeIndex = current ? onboardingStageIndex(current.stage) : -1;

  async function copySupportReference() {
    if (!current?.supportReference) return;
    await navigator.clipboard.writeText(current.supportReference);
    setCopied(true);
  }

  return (
    <SaasAuthShell
      compact
      eyebrow={
        supportRequired
          ? "Setup needs attention"
          : complete
            ? "Workspace ready"
            : "Preparing workspace"
      }
      title={
        supportRequired
          ? "We need to finish this with you"
          : complete
            ? "Your organization is ready"
            : "Your workspace is taking shape"
      }
      description={
        supportRequired
          ? "Automatic recovery has stopped safely. Share the reference below with support."
          : complete
            ? "The tenant boundary, first space, and runtime are ready for your first agent run."
            : "You can keep this page open. Each step below comes from the provisioning service."
      }
      step={{ current: 3, total: 3, label: "Provision workspace" }}
    >
      {status.isPending ? (
        <div className="grid min-h-44 place-items-center text-center" role="status">
          <div>
            <Clock3 className="mx-auto mb-3 size-5 animate-pulse text-primary motion-reduce:animate-none" />
            <p className="text-sm text-muted-foreground">Reading the latest setup state…</p>
          </div>
        </div>
      ) : status.isError || !current ? (
        <div className="space-y-4">
          <Alert variant="destructive">
            <AlertTriangle className="size-4" />
            <AlertTitle>We could not load setup status</AlertTitle>
            <AlertDescription>{onboardingErrorMessage(status.error)}</AlertDescription>
          </Alert>
          {status.error instanceof OnboardingApiError && status.error.status === 401 ? (
            <Button asChild size="lg" className="h-11 w-full">
              <Link
                to={`/saas/login?return_to=${encodeURIComponent("/signup/status")}`}
                componentId="saas_status.sign_in"
              >
                Sign in to continue
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
          ) : (
            <Button
              type="button"
              variant="outline"
              size="lg"
              className="h-11 w-full"
              onClick={() => void status.refetch()}
              componentId="saas_status.retry"
            >
              <RotateCcw data-icon="inline-start" />
              Try again
            </Button>
          )}
        </div>
      ) : supportRequired ? (
        <div className="space-y-5">
          <Alert variant="destructive">
            <LifeBuoy className="size-4" />
            <AlertTitle>Support reference</AlertTitle>
            <AlertDescription>
              <code className="mt-2 block break-all rounded-md bg-muted px-3 py-2 font-mono text-xs text-foreground">
                {current.supportReference ?? "Reference unavailable"}
              </code>
            </AlertDescription>
          </Alert>
          {current.supportReference ? (
            <Button
              type="button"
              variant="outline"
              size="lg"
              className="h-11 w-full"
              onClick={() => void copySupportReference()}
              componentId="saas_status.copy_reference"
            >
              <Copy data-icon="inline-start" />
              {copied ? "Copied" : "Copy support reference"}
            </Button>
          ) : null}
        </div>
      ) : (
        <div className="space-y-6">
          {current.state === "recovering" ? (
            <Alert>
              <RotateCcw className="size-4 text-primary" />
              <AlertTitle>Automatic recovery is running</AlertTitle>
              <AlertDescription>
                Your completed setup work is preserved while the service retries safely.
              </AlertDescription>
            </Alert>
          ) : null}

          <ol className="space-y-1" aria-live="polite" aria-label="Workspace setup progress">
            {ONBOARDING_STAGES.map((stage, index) => {
              const done = complete || index < activeIndex;
              const active = !complete && index === activeIndex;
              return (
                <li key={stage.key} className="relative flex gap-3 pb-5 last:pb-0">
                  {index < ONBOARDING_STAGES.length - 1 ? (
                    <span
                      aria-hidden="true"
                      className={cn(
                        "absolute left-[11px] top-7 h-[calc(100%-1rem)] w-px",
                        done ? "bg-primary/60" : "bg-border",
                      )}
                    />
                  ) : null}
                  <span
                    className={cn(
                      "relative z-10 grid size-6 shrink-0 place-items-center rounded-full border text-[10px]",
                      done
                        ? "border-primary bg-primary text-primary-foreground"
                        : active
                          ? "border-primary bg-primary/10 text-primary ring-4 ring-primary/[0.08]"
                          : "border-border bg-card text-muted-foreground",
                    )}
                  >
                    {done ? (
                      <Check className="size-3" />
                    ) : active ? (
                      <Clock3 className="size-3" />
                    ) : (
                      index + 1
                    )}
                  </span>
                  <div className="min-w-0 pt-0.5">
                    <p
                      className={cn(
                        "text-sm font-medium",
                        !done && !active && "text-muted-foreground",
                      )}
                    >
                      {stage.label}
                    </p>
                    <p className="mt-0.5 text-xs leading-5 text-muted-foreground">
                      {stage.description}
                    </p>
                  </div>
                </li>
              );
            })}
          </ol>

          {complete ? (
            <Button
              type="button"
              size="lg"
              className="h-11 w-full"
              onClick={() => window.location.assign("/")}
              componentId="saas_status.open_workspace"
            >
              Open workspace
              <ArrowRight data-icon="inline-end" />
            </Button>
          ) : (
            <p className="text-center text-xs text-muted-foreground">
              Last update {new Date(current.updatedAt).toLocaleTimeString()}
            </p>
          )}
        </div>
      )}
    </SaasAuthShell>
  );
}
